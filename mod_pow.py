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