from ext_gcd import ext_gcd

def mod_invers (a, b):

    hasil, koef = ext_gcd(a, b)

    if hasil != 1:
        raise ValueError(f"Inverse tidak ada karena gcd({a}, {b}) = {hasil} ≠ 1")

    else:
        return koef[0] % b

    
