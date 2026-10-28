# Math
import secrets

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
    return 

def mod_pow (base, exp, mod):

    if mod == 1:
        return 0

    hasil = 1
    base = base % mod

    while exp > 0:
        if (exp % 2) == 1:
            hasil = (hasil * base) % mod

        base = (base * base) % mod  
        exp = exp // 2

    return hasil

def generate_prime(bits):
    if bits < 2: raise ValueError("bits minimal 2")
    while True:
        # Menggunakan secrets.randbits yang aman
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if miller_rabin(candidate, 40):
            return 

def ext_gcd (a, b):

   x0, x1, y0, y1 = 1, 0, 0, 1
   
   while b != 0:
       q = a // b
       a, b = b, a % b
       x0, x1 = x1, x0 - q * x1
       y0, y1 = y1, y0 - q * y1

   return a, [x0, y0]


def crt_reconstruct(m_p, m_q, p, q, q_inv):
    h = (q_inv * ((m_p - m_q) % p)) % p
    return m_q + h * q