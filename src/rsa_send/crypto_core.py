# Cryptography
import hmac
import hashlib
import math
import secrets

from rsa_send.modular_math import generate_prime, crt_reconstruct, mod_pow, mod_invers


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


KEM_INFO = b"RSA-KEM TrafficKey"


def _int_to_bytes(z: int, n: int) -> bytes:
    k = (n.bit_length() + 7) // 8
    return z.to_bytes(k, "big")


def _derive_traffic_key(z: int, n: int, key_len: int, salt:bytes | None = None) -> bytes:
    z_bytes = _int_to_bytes(z, n)
    prk = hkdf_extract(salt, z_bytes)
    
    return hkdf_expand(prk, KEM_INFO, key_len)


def rsa_kem_encapsulate(public_key: tuple[int, int], key_len: int = 32, salt: bytes | None = None) -> tuple[bytes, bytes]:
    e, n = public_key

    # z acak yang aman secara kriptografi, 2 <= z <= n-2
    z = secrets.randbelow(n - 3) + 2

    c = mod_pow(z, e, n)
    c_bytes = _int_to_bytes(c, n)
    traffic_key = _derive_traffic_key(z, n, key_len, salt)
    return c_bytes, traffic_key

PUBLIC_EXPONENT = 65537


def rsa_generate_key_crt(bits: int = 2048) -> tuple[tuple[int, int], tuple[int, ...]]:
    if bits < 16 or bits % 2 != 0:
        raise ValueError("bits harus genap dan minimal 16.")

    e = PUBLIC_EXPONENT
    half = bits // 2

    while True:
        p = generate_prime(half)
        q = generate_prime(half)

        # p dan q harus berbeda
        if p == q:
            continue

        # e harus koprima dengan (p-1) dan (q-1), supaya d ada
        if math.gcd(e, p - 1) != 1 or math.gcd(e, q - 1) != 1:
            continue

        n = p * q

        # Pastikan n benar-benar berukuran 'bits'
        if n.bit_length() != bits:
            continue

        break

    phi = (p - 1) * (q - 1)
    d = mod_invers(e, phi)

    # Parameter CRT
    dp = d % (p - 1)
    dq = d % (q - 1)
    q_inv = mod_invers(q, p)

    public_key = (e, n)
    private_key_crt = (n, d, p, q, dp, dq, q_inv)
    return public_key, private_key_crt

def rsa_kem_decapsulate_crt(c_input: int, private_key_crt: tuple, key_len: int = 32, salt: bytes | None = None) -> bytes:
    n, d, p, q, dp, dq, q_inv = private_key_crt

    if isinstance(c_input, bytes):
        c = int.from_bytes(c_input, "big")
    else:
        c = c_input

    if not (1 < c < n):
        raise ValueError("Ciphertext C di luar rentang yang valid (1 < C < n).")

    # Dekripsi terpisah modulo p dan modulo q
    m_p = mod_pow(c % p, dp, p)
    m_q = mod_pow(c % q, dq, q)

    # Gabungkan kembali dengan Garner's formula
    z = crt_reconstruct(m_p, m_q, p, q, q_inv)

    # Turunan kunci dengan salt yang identik dengan sisi client
    return _derive_traffic_key(z, n, key_len, salt)
