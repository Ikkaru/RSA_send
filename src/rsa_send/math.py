# Math
import secrets
import hmac
import hashlib

def miller_rabin(n, k):
    if n < 2: return False
    # Optimasi: Saring dengan prime kecil sebelum komputasi berat
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small_primes:
        if n % p == 0:
            return n == p
            
    d = n - 1
    r = 0
    while d % 2 == 0:
        r += 1
        d //= 2
        
    for _ in range(k):
        # Menggunakan secrets untuk keamanan kriptografi
        a = secrets.randbelow(n - 3) + 2 
        x = mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    if bits < 2: raise ValueError("bits minimal 2")
    while True:
        # Menggunakan secrets.randbits yang aman
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if miller_rabin(candidate, 40):
            return candidate

def crt_reconstruct(m_p, m_q, p, q, q_inv):
    h = (q_inv * ((m_p - m_q) % p)) % p
    return m_q + h * q