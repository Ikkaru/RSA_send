import json
import os
import socket
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # Menggunakan External Library hanya Untuk Algoritma AES
from rsa_send.certificate import sign_certificate, verify_certificate
from rsa_send.crypto_core import (
    rsa_generate_key_crt,
    rsa_kem_decapsulate_crt,
    rsa_kem_encapsulate,
)

CA_KEY_PATH = Path(__file__).with_name("ca_key.json")


def _load_or_create_ca_keys() -> tuple[tuple[int, int], tuple[int, ...]]:
    """Use one local CA across separate server and client processes."""
    if CA_KEY_PATH.exists():
        data = json.loads(CA_KEY_PATH.read_text(encoding="utf-8"))
        public_key = tuple(data["public_key"])
        private_key = tuple(data["private_key"])
        return public_key, private_key

    public_key, private_key = rsa_generate_key_crt(2048)
    CA_KEY_PATH.write_text(
        json.dumps({"public_key": list(public_key), "private_key": list(private_key)}),
        encoding="utf-8",
    )
    return public_key, private_key


ca_pub_key, ca_priv_key = _load_or_create_ca_keys()


def send_exact(sock: socket.socket, data: bytes):
    sock.sendall(data)


def recv_exact(sock: socket.socket, length: int) -> bytes:
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise ConnectionError("Disconnected While Reading Data")
        buf.extend(chunk)
    return bytes(buf)


def unpack_image_payload(payload: bytes) -> tuple[bytes, tuple | None, str | None]:
    raw_bytes = payload
    shape = None
    dtype = None
    try:
        if len(payload) > 4:
            meta_len = int.from_bytes(payload[:4], "big")
            if 0 < meta_len < 4096 and len(payload) >= 4 + meta_len:
                meta = json.loads(payload[4 : 4 + meta_len].decode("utf-8"))
                if "shape" in meta and "dtype" in meta:
                    shape = tuple(meta["shape"])
                    dtype = str(meta["dtype"])
                    raw_bytes = payload[4 + meta_len :]
    except Exception:
        pass
    return raw_bytes, shape, dtype


class TLSRecordLayer:
    CHUNK_SIZE = 16 * 1024

    def __init__(self, traffic_key: bytes):
        self.aesgcm = AESGCM(traffic_key)
        self.seq_num = 0

    def _generate_nonce(self) -> bytes:
        nonce = b"\x00" * 4 + self.seq_num.to_bytes(8, "big")
        self.seq_num += 1
        return nonce

    def send_record(self, sock: socket.socket, raw_data: bytes):
        for i in range(0, len(raw_data), self.CHUNK_SIZE):
            chunk = raw_data[i : i + self.CHUNK_SIZE]
            nonce = self._generate_nonce()
            ciphertext = self.aesgcm.encrypt(nonce, chunk, None)
            payload = nonce + ciphertext
            header = b"\x17\x03\x04" + len(payload).to_bytes(2, "big")
            send_exact(sock, header + payload)

    def recv_record(self, sock: socket.socket) -> bytes:
        header = recv_exact(sock, 5)
        payload_len = int.from_bytes(header[3:5], "big")
        payload = recv_exact(sock, payload_len)
        nonce = payload[:12]
        ciphertext = payload[12:]
        return self.aesgcm.decrypt(nonce, ciphertext, None)

    def send_message(self, sock: socket.socket, raw_data: bytes):
        """Sends a framed message of arbitrary length using encrypted records."""
        total_len = len(raw_data)
        send_exact(sock, total_len.to_bytes(8, "big"))
        self.send_record(sock, raw_data)

    def recv_message(self, sock: socket.socket) -> bytes:
        """Receives a complete framed message across records."""
        total_len_bytes = recv_exact(sock, 8)
        total_len = int.from_bytes(total_len_bytes, "big")

        received_chunks = []
        received_len = 0
        while received_len < total_len:
            chunk = self.recv_record(sock)
            received_chunks.append(chunk)
            received_len += len(chunk)

        return b"".join(received_chunks)


class TLSClientSession:
    """Manages an active client connection and TLS session state."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8443, ca_pub_key: tuple[int, int] = ca_pub_key):
        self.host = host
        self.port = port
        self.ca_pub_key = ca_pub_key
        self.sock: socket.socket | None = None
        self.traffic_key: bytes | None = None
        self.record_layer: TLSRecordLayer | None = None
        self.is_connected = False

    def perform_handshake(self) -> list[dict[str, str]]:
        """Connects TCP and performs complete TLS Handshake with RSA-KEM & Certificate verification.
        Derives symmetric traffic_key. Does NOT send image.
        Returns list of structured log entries.
        """
        logs: list[dict[str, str]] = []

        def log(tag: str, msg: str):
            logs.append({"time": datetime.now().strftime("%H:%M:%S"), "tag": tag, "msg": msg})

        log("CLIENT", f"Connecting TCP socket to {self.host}:{self.port}...")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        log("CLIENT", "TCP Socket connected. Initiating TLS 1.3 / RSA-KEM Handshake...")

        # 1. Kirim Client Random
        client_random = os.urandom(32)
        send_exact(self.sock, client_random)
        log("HANDSHAKE", f"Sent Client Random: {client_random[:8].hex()}... (32 bytes)")

        # 2. Terima Server Random + Certificate
        server_random = recv_exact(self.sock, 32)
        log("HANDSHAKE", f"Received Server Random: {server_random[:8].hex()}... (32 bytes)")

        cert_len = int.from_bytes(recv_exact(self.sock, 4), "big")
        cert_data = json.loads(recv_exact(self.sock, cert_len).decode("utf-8"))
        server_pub_key = (cert_data["e"], cert_data["n"])
        signature = cert_data["signature"]
        log("CERTIFICATE", f"Received Server Certificate (e={server_pub_key[0]}, n={str(server_pub_key[1])[:14]}...)")

        # Verifikasi Sertifikat Server dengan Public Key CA
        log("CERTIFICATE", "Verifying Server Certificate signature against trusted CA Public Key...")
        is_valid = verify_certificate(server_pub_key, signature, self.ca_pub_key)
        if not is_valid:
            self.close()
            log("ERROR", "VERIFIKASI GAGAL: Sertifikat Server tidak valid atau telah dipalsukan!")
            raise Exception("VERIFIKASI GAGAL: Sertifikat Server tidak valid atau telah dipalsukan!")

        log("SUCCESS", "Server Certificate VALID! Identity trusted by Certificate Authority.")

        # 3. Enkapsulasi KEM
        salt = client_random + server_random
        c_bytes, traffic_key = rsa_kem_encapsulate(server_pub_key, key_len=16, salt=salt)
        log("KEM", f"RSA-KEM Encapsulation: Generated Ciphertext ({len(c_bytes)} bytes) & derived 128-bit AES-GCM Traffic Key")

        # 4. Kirim c_bytes
        send_exact(self.sock, c_bytes)
        log("HANDSHAKE", "Sent KEM Ciphertext to Server.")

        # Simpan sesi aktif
        self.traffic_key = traffic_key
        self.record_layer = TLSRecordLayer(traffic_key)
        self.is_connected = True
        log("SUCCESS", f"TLS Handshake Complete! Symmetric Traffic Key ({traffic_key.hex()[:8]}...) derived on both sides.")
        log("CLIENT", "Secure channel is now READY. Client can proceed to send images.")
        return logs

    def send_image(self, image_bytes: bytes, shape: tuple | None = None, dtype: str | None = None) -> list[dict[str, str]]:
        if not self.is_connected or not self.sock or not self.record_layer:
            raise ConnectionError("Koneksi belum terjalin atau handshake belum dilakukan.")

        logs: list[dict[str, str]] = []

        def log(tag: str, msg: str):
            logs.append({"time": datetime.now().strftime("%H:%M:%S"), "tag": tag, "msg": msg})

        if shape is not None and dtype is not None:
            meta_json = json.dumps({"shape": list(shape), "dtype": dtype}).encode("utf-8")
            payload = len(meta_json).to_bytes(4, "big") + meta_json + image_bytes
        else:
            payload = image_bytes

        log("TRANSFER", f"Encrypting image ({len(image_bytes):,} raw bytes, shape: {shape}) using AES-GCM...")
        self.record_layer.send_message(self.sock, payload)
        log("SUCCESS", f"Image ({len(payload):,} bytes encrypted) sent successfully over TLS Record Layer!")
        return logs

    def close(self):
        self.is_connected = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


class TLSServerNetwork:
    """Server listener that accepts connections, conducts TLS handshakes, and maintains active sessions."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8443):
        self.host = host
        self.port = port
        self.pub_key, self.priv_key_crt = rsa_generate_key_crt(2048)
        self.server_sock: socket.socket | None = None
        self._running = False
        self.active_conn: socket.socket | None = None

    def start_listening(self):
        if self.server_sock is None:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind((self.host, self.port))
            self.server_sock.listen(5)
            self._running = True
            print(f"[Server] Listening di {self.host}:{self.port}...")

    def accept_client_and_handshake(self, log_fn) -> tuple[socket.socket, TLSRecordLayer, str]:
        """Accepts a client connection and executes server-side TLS handshake."""
        if not self.server_sock:
            self.start_listening()

        conn, addr = self.server_sock.accept()
        addr_str = f"{addr[0]}:{addr[1]}"
        log_fn("SERVER", f"Accepted TCP connection from Client: {addr_str}")

        try:
            # 1. Terima Client Random
            client_random = recv_exact(conn, 32)
            log_fn("HANDSHAKE", f"Received Client Random: {client_random[:8].hex()}... (32 bytes)")

            # 2. Kirim Server Random + Certificate
            server_random = os.urandom(32)
            send_exact(conn, server_random)
            log_fn("HANDSHAKE", f"Generated & sent Server Random: {server_random[:8].hex()}... (32 bytes)")

            signature = sign_certificate(self.pub_key, (ca_priv_key[1], ca_pub_key[1]))
            e, n = self.pub_key
            cert_payload = json.dumps({"e": e, "n": n, "signature": signature}).encode("utf-8")
            send_exact(conn, len(cert_payload).to_bytes(4, "big") + cert_payload)
            log_fn("CERTIFICATE", f"Sent CA-signed Server Certificate to Client (e={e}, signature={str(signature)[:12]}...)")

            # 3. Terima Ciphertext c_bytes
            k_bytes = (n.bit_length() + 7) // 8
            c_bytes = recv_exact(conn, k_bytes)
            log_fn("HANDSHAKE", f"Received KEM Ciphertext ({len(c_bytes)} bytes)")

            # 4. Dekapsulasi KEM
            salt = client_random + server_random
            traffic_key = rsa_kem_decapsulate_crt(c_bytes, self.priv_key_crt, key_len=16, salt=salt)
            log_fn("KEM", f"RSA-KEM CRT Decapsulation: Derived symmetric Traffic Key ({traffic_key.hex()[:8]}...) via HKDF")

            record_layer = TLSRecordLayer(traffic_key)
            log_fn("SUCCESS", f"TLS Handshake Complete! Symmetric session established with Client ({addr_str}).")
            log_fn("SERVER", "Awaiting incoming image transfer on encrypted channel...")
            return conn, record_layer, addr_str
        except Exception as e:
            conn.close()
            raise e

    def close(self):
        self._running = False
        if self.active_conn:
            try:
                self.active_conn.close()
            except Exception:
                pass
            self.active_conn = None
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
            self.server_sock = None
