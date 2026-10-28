# Simulate TLS Certificate Signing and Verifying
import hashlib
from rsa_send.modular_math import mod_pow


def sign_certificate(
    server_pub_key: tuple[int, int], ca_priv_key: tuple[int, int]
) -> int:
  d_ca, n_ca = ca_priv_key
  e_s, n_s = server_pub_key

  cert_bytes = f"{e_s}:{n_s}".encode()
  hash_val = int.from_bytes(hashlib.sha256(cert_bytes).digest(), "big")

  # Signature = Hash^d_ca mod n_ca
  return mod_pow(hash_val, d_ca, n_ca)


def verify_certificate(
    server_pub_key: tuple[int, int],
    signature: int,
    ca_pub_key: tuple[int, int],
) -> bool:
  e_ca, n_ca = ca_pub_key
  e_s, n_s = server_pub_key

  cert_bytes = f"{e_s}:{n_s}".encode()
  hash_val = int.from_bytes(hashlib.sha256(cert_bytes).digest(), "big")

  # Decrypt signature: Hash_check = Signature^e_ca mod n_ca
  hash_check = mod_pow(signature, e_ca, n_ca)
  return hash_val == hash_check