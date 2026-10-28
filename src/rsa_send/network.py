import json
import os
import socket
from rsa_send.certificate import sign_certificate, verify_certificate
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # Menggunakan External Library hanya Untuk Algoritma AES

from rsa_send.crypto_core import (
    rsa_generate_key_crt,
    rsa_kem_decapsulate_crt,
    rsa_kem_encapsulate,
)

# Simulasi Certificate Authority, Generate public dan private key
ca_pub_key, ca_priv_key = rsa_generate_key_crt(2048)


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


class TLSServerNetwork:
    def __init__(self, host: str = "127.0.0.1", port: int = 8443):
        self.host = host
        self.port = port
        self.pub_key, self.priv_key_crt = rsa_generate_key_crt(2048)

    def listen_and_receive(self) -> bytes:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind((self.host, self.port))
        server_sock.listen(1)
        print(f"[Server] Listening di {self.host}:{self.port}...")

        conn, addr = server_sock.accept()
        print(f"[Server] Terhubung dengan Client: {addr}")

        # 1. Terima Client Random
        client_random = recv_exact(conn, 32)

        # 2. Kirim Server Random + Certificate
        server_random = os.urandom(32)
        send_exact(conn, server_random)

        signature = sign_certificate(self.pub_key, (ca_priv_key[1], ca_pub_key[1]))

        e, n = self.pub_key
        # PERBAIKAN: pakai 'signature' variabel lokal
        cert_payload = json.dumps({"e": e, "n": n, "signature": signature}).encode("utf-8")
        send_exact(conn, len(cert_payload).to_bytes(4, "big") + cert_payload)

        # 3. Terima Ciphertext c_bytes
        k_bytes = (n.bit_length() + 7) // 8
        c_bytes = recv_exact(conn, k_bytes)

        # 4. Dekapsulasi KEM
        salt = client_random + server_random
        traffic_key = rsa_kem_decapsulate_crt(
            c_bytes, self.priv_key_crt, key_len=16, salt=salt
        )
        print("[Server] Handshake Sukses! Traffic Key berhasil diturunkan.")

        # Record Layer
        record_layer = TLSRecordLayer(traffic_key)
        received_chunks = []

        try:
            while True:
                chunk = record_layer.recv_record(conn)
                received_chunks.append(chunk)
        except ConnectionError:
            pass

        conn.close()
        server_sock.close()

        full_image_bytes = b"".join(received_chunks)
        print(f"[Server] Berhasil menerima & mendekripsi gambar ({len(full_image_bytes)} bytes)!")
        return full_image_bytes


class TLSClientNetwork:
    def __init__(self, host: str = "127.0.0.1", port: int = 8443, ca_pub_key: tuple[int, int] = ca_pub_key):
        self.host = host
        self.port = port
        self.ca_pub_key = ca_pub_key

    def send_image(self, image_bytes: bytes):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))

        # 1. Kirim Client Random
        client_random = os.urandom(32)
        send_exact(sock, client_random)

        # 2. Terima Server Random + Certificate
        server_random = recv_exact(sock, 32)

        cert_len = int.from_bytes(recv_exact(sock, 4), "big")
        cert_data = json.loads(recv_exact(sock, cert_len).decode("utf-8"))

        server_pub_key = (cert_data["e"], cert_data["n"])
        signature = cert_data["signature"]

        is_valid = verify_certificate(server_pub_key, signature, self.ca_pub_key)

        if not is_valid:
            sock.close()
            raise Exception("VERIFIKASI GAGAL: Sertifikat Server tidak valid atau telah dipalsukan!")

        print("[Client] Sertifikat Server Terverifikasi oleh CA!")

        # 3. Enkapsulasi KEM
        salt = client_random + server_random
        c_bytes, traffic_key = rsa_kem_encapsulate(server_pub_key, key_len=16, salt=salt)

        # 4. Kirim c_bytes
        send_exact(sock, c_bytes)
        print("[Client] Handshake Sukses! Traffic Key berhasil diturunkan.")

        # Record Layer
        record_layer = TLSRecordLayer(traffic_key)
        record_layer.send_record(sock, image_bytes)
        print(f"[Client] Berhasil mengenkripsi & mengirim gambar ({len(image_bytes)} bytes)!")

        sock.close()