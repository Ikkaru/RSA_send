# Cryptography
# Cryptography
import hmac
import hashlib
import math
import secrets

from .math import mod_pow


def hkdf_extract(salt: bytes | None, ikm: bytes, hash_alg=hashlib.sha256) -> bytes:
    hash_len = hash_alg().digest_size

    # Jika tidak menggunakan salt, isi salt dengan bytes kosong
    if not salt:
        salt = b"\x00" * hash_len

    return hmac.new(salt, ikm, hash_alg).digest()


# Output AES key
def hkdf_expand(prk: bytes, info: bytes, length: int, hash_alg=hashlib.sha256) -> bytes:
    hash_len = hash_alg().digest_size

    # Batas maksimum keluaran sesuai standar RFC 5869
    if length > 255 * hash_len:
        raise ValueError("Ukuran length melebihi batas maksimum HKDF-Expand.")

    okm = b""
    t = b""
    n = math.ceil(length / hash_len)

    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hash_alg).digest()
        okm += t

    return okm[:length]


# HKDF Wrapper
def hkdf(ikm: bytes, length: int, salt: bytes | None = None, info: bytes = b"", hash_alg=hashlib.sha256) -> bytes:
    prk = hkdf_extract(salt, ikm, hash_alg)
    return hkdf_expand(prk, info, length, hash_alg)

KEM_SALT = None
KEM_INFO = b"RSA-KEM TrafficKey"


def _int_to_bytes(z: int, n: int) -> bytes:
    k = (n.bit_length() + 7) // 8
    return z.to_bytes(k, "big")


def _derive_traffic_key(z: int, n: int, key_len: int) -> bytes:
    z_bytes = _int_to_bytes(z, n)
    prk = hkdf_extract(KEM_SALT, z_bytes)
    return hkdf_expand(prk, KEM_INFO, key_len)


def rsa_kem_encapsulate(public_key: tuple[int, int], key_len: int = 32) -> tuple[int, bytes]:
    e, n = public_key

    # z acak yang aman secara kriptografi, 2 <= z <= n-2
    z = secrets.randbelow(n - 3) + 2

    c = mod_pow(z, e, n)
    traffic_key = _derive_traffic_key(z, n, key_len)
    return c, traffic_key