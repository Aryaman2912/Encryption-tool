def mod_exp(num, e, mod):
    ciphertext = 1

    num = num % mod
    if num == 0:
        return 0

    while e > 0:
        if e % 2:
            ciphertext = (ciphertext * num) % mod
        
        e = e // 2
        num = (num * num) % mod
    
    return ciphertext

def multiplicative_inverse(e, phi):
    if e == 0:
        return 0,1,phi
    
    x1, y1, gcd = multiplicative_inverse(phi % e, e)

    x = y1 - (phi // e) * x1
    y = x1

    return x, y, gcd

def get_primes():
    pass

def key_gen():
    p1, p2 = get_primes()

def encrypt(pk, message):
    #ct = (message ^ e) mod phi
    e, mod = pk
    ciphertext = mod_exp(message,e,mod)
    return ciphertext
    
def decrypt(pk, ciphertext):
    d, mod = pk
    message = mod_exp(ciphertext, e, mod)
    return message

message = 'this is a message'
p = 67280421310721
q = 999999000001
n = p * q
phi = (p - 1) * (q - 1)
mod = phi
e = 65537
d = multiplicative_inverse(e,phi)
print(decrypt((d,phi),encrypt((e,phi),123524)))