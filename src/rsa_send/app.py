from __future__ import annotations

import base64
import mimetypes
import socket
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

import webview

from rsa_send.image_processing import ImageProcessor
from rsa_send.network import (
    TLSClientSession,
    TLSServerNetwork,
    unpack_image_payload,
)


FRONTEND_PATH = Path(__file__).parent / "frontend" / "index.html"


class Bridge:
	"""API surface exposed to pywebview JavaScript frontend."""

	def __init__(self) -> None:
		self._window: Any = None
		self._lock = threading.Lock()

		# Client state
		self._client_session: TLSClientSession | None = None
		self._client_state: str = "closed"  # "closed", "connecting", "connected"

		# Server state
		self._server_thread: threading.Thread | None = None
		self._server_network: TLSServerNetwork | None = None
		self._server_state: str = "idle"  # "idle", "listening", "connected"
		self._server_logs: list[dict[str, str]] = []
		self._transfer_id: int = 0
		self._last_image_bytes: int = 0
		self._last_image_url: str = ""

	def get_initial_state(self) -> dict[str, Any]:
		return {
			"status": "ready",
			"frontend": str(FRONTEND_PATH),
			"client_state": self._client_state,
			"server_state": self._server_state,
		}

	def select_image(self) -> dict[str, Any]:
		if self._window is None:
			return {"status": "error", "message": "Window desktop belum siap."}

		try:
			selected = self._window.create_file_dialog(
				webview.OPEN_DIALOG,
				allow_multiple=False,
				file_types=("Image files (*.png;*.jpg;*.jpeg;*.webp;*.bmp)",),
			)
			if not selected:
				return {"status": "cancelled"}

			image_path = str(selected[0])
			mime_type = mimetypes.guess_type(image_path)[0] or "application/octet-stream"
			encoded = base64.b64encode(Path(image_path).read_bytes()).decode("ascii")
			return {
				"status": "selected",
				"path": image_path,
				"name": Path(image_path).name,
				"data_url": f"data:{mime_type};base64,{encoded}",
			}
		except Exception as error:
			return {"status": "error", "message": str(error)}

	# ===================== CLIENT ENDPOINTS =====================

	def connect_client(self, host: str, port: int) -> dict[str, Any]:
		"""Executes TLS 1.3 handshake with Server. Does NOT send image."""
		with self._lock:
			if self._client_session and self._client_session.is_connected:
				return {
					"status": "connected",
					"message": "Client sudah terhubung.",
					"logs": [],
				}

		try:
			session = TLSClientSession(host=host, port=int(port))
			logs = session.perform_handshake()
			with self._lock:
				self._client_session = session
				self._client_state = "connected"

			key_preview = session.traffic_key.hex()[:8] if session.traffic_key else ""
			return {
				"status": "connected",
				"message": f"Handshake Sukses! Traffic key ({key_preview}...) aktif.",
				"logs": logs,
				"key_preview": key_preview,
			}
		except Exception as error:
			with self._lock:
				self._client_state = "closed"
				if self._client_session:
					self._client_session.close()
					self._client_session = None
			return {"status": "error", "message": str(error)}

	def disconnect_client(self) -> dict[str, Any]:
		"""Gracefully disconnects client session."""
		with self._lock:
			if self._client_session:
				self._client_session.close()
				self._client_session = None
			self._client_state = "closed"
		return {"status": "closed", "message": "Koneksi diputus oleh client."}

	def send_image(self, image_path: str) -> dict[str, Any]:
		"""Sends image over the established TLS session."""
		if not image_path:
			return {"status": "error", "message": "Pilih gambar terlebih dahulu."}

		with self._lock:
			session = self._client_session
			if not session or not session.is_connected:
				return {
					"status": "error",
					"message": "Belum terhubung ke server. Klik 'Connect' terlebih dahulu untuk melakukan TLS handshake.",
				}

		try:
			raw_bytes, shape, dtype = ImageProcessor(image_path).to_bytes()
			logs = session.send_image(raw_bytes, shape=shape, dtype=dtype)
			return {
				"status": "sent",
				"bytes": len(raw_bytes),
				"shape": list(shape),
				"dtype": dtype,
				"logs": logs,
			}
		except Exception as error:
			return {"status": "error", "message": str(error)}

	# ===================== SERVER ENDPOINTS =====================

	def _add_server_log(self, tag: str, msg: str) -> None:
		entry = {"time": datetime.now().strftime("%H:%M:%S"), "tag": tag, "msg": msg}
		with self._lock:
			self._server_logs.append(entry)

	def start_server(self, host: str, port: int) -> dict[str, str]:
		with self._lock:
			if self._server_thread and self._server_thread.is_alive():
				return {"status": "listening", "message": f"Server sudah aktif mendengarkan di {host}:{port}."}

			self._server_state = "listening"
			self._server_logs.clear()

		def serve() -> None:
			server = TLSServerNetwork(host=host, port=int(port))
			with self._lock:
				self._server_network = server

			try:
				server.start_listening()
				self._add_server_log("SERVER", f"Server listening on {host}:{port}. Menunggu Client...")

				while server._running:
					try:
						with self._lock:
							self._server_state = "listening"

						conn, record_layer, addr_str = server.accept_client_and_handshake(self._add_server_log)
						server.active_conn = conn

						with self._lock:
							self._server_state = "connected"
					except (socket.error, OSError):
						break
					except Exception as hs_err:
						self._add_server_log("ERROR", f"Handshake gagal: {hs_err}")
						continue

					# Loop membaca pengiriman gambar dari client ini
					try:
						while server._running:
							payload = record_layer.recv_message(conn)
							raw_bytes, shape, dtype = unpack_image_payload(payload)
							self._add_server_log("TRANSFER", f"Diterima & didekripsi paket gambar ({len(raw_bytes):,} bytes).")

							image_url = ""
							if shape and dtype:
								try:
									pil_img = ImageProcessor.to_image(raw_bytes, shape, dtype)
									output_path = FRONTEND_PATH.parent / "received_image.png"
									pil_img.save(output_path, format="PNG")
									image_url = f"received_image.png?t={int(output_path.stat().st_mtime_ns)}"
									self._add_server_log("IMAGE", f"Rekonstruksi citra lossless selesai ({shape[1]}x{shape[0]} piksel).")
								except Exception as conv_err:
									self._add_server_log("ERROR", f"Gagal rekonstruksi citra: {conv_err}")

							with self._lock:
								self._transfer_id += 1
								self._last_image_bytes = len(raw_bytes)
								self._last_image_url = image_url

					except (ConnectionError, OSError):
						self._add_server_log("INFO", f"Koneksi dengan Client {addr_str} ditutup.")
					finally:
						conn.close()
						server.active_conn = None
						with self._lock:
							if server._running:
								self._server_state = "listening"
						self._add_server_log("SERVER", "Siap menunggu koneksi Client berikutnya...")

			except Exception as error:
				with self._lock:
					self._server_state = "error"
				self._add_server_log("ERROR", f"Server error: {error}")
			finally:
				server.close()
				with self._lock:
					self._server_network = None
					self._server_state = "idle"

		self._server_thread = threading.Thread(target=serve, daemon=True)
		self._server_thread.start()
		return {"status": "listening", "message": f"Menunggu koneksi di {host}:{port}."}

	def stop_server(self) -> dict[str, str]:
		with self._lock:
			if self._server_network:
				self._server_network.close()
				self._server_network = None
			self._server_state = "idle"
		self._add_server_log("SERVER", "Server dihentikan oleh pengguna.")
		return {"status": "stopped", "message": "Server dihentikan."}

	def get_server_status(self, last_log_index: int = 0) -> dict[str, Any]:
		with self._lock:
			return {
				"server_state": self._server_state,
				"transfer_id": self._transfer_id,
				"bytes": self._last_image_bytes,
				"image_url": self._last_image_url,
				"new_logs": self._server_logs[last_log_index:],
				"total_logs": len(self._server_logs),
			}


def launch() -> None:
	if not FRONTEND_PATH.exists():
		raise FileNotFoundError(f"Frontend tidak ditemukan: {FRONTEND_PATH}")

	bridge = Bridge()
	window = webview.create_window(
		"RSA Send",
		FRONTEND_PATH.as_uri(),
		js_api=bridge,
		width=1360,
		height=900,
		min_size=(960, 680),
	)
	bridge._window = window
	webview.start()
