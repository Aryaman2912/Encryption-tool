from utils import *
from Crypto.Util import number

def get_primes():
    p = number.getPrime(1024)
    q = number.getPrime(1024)
    return (p,q)

def key_gen():
    p, q = get_primes()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = multiplicative_inverse(e,phi)
    return ((e,n),(d,n))


def encrypt(public_key, message):
    message_int = int(hex_to_binary(ascii_to_hex(message)),2)
    e, mod = public_key
    ciphertext = mod_exp(message_int,e,mod)
    return ciphertext

def decrypt(private_key, ciphertext):
    d, mod = private_key
    message_int = mod_exp(ciphertext, d, mod)
    message = hex_to_ascii(binary_to_hex(int_to_binary(message_int)))
    return message

message = 'this is a message'
public_key, private_key = key_gen()
ciphertext = encrypt(public_key,message)
plaintext = decrypt(private_key,ciphertext)
print(plaintext)