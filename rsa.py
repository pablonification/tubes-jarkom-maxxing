import random
import socket

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Menghubungkan ke alamat IP publik
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip

def gcd(a,b):
    while b != 0:
        a,b = b, a % b
    return a

def is_prime(n):
    if n <= 1:
        return False
    for _ in range(5):
        a = random.randint(2, n-1)
        if gcd(a,n) != 1:
            return False
        if pow(a, n-1, n) != 1:
            return False
    return True

def generate_prime_candidate(length):
    p = random.getrandbits(length)
    p |= (1 << length - 1) | 1
    return p

def generate_prime_number(length=512):
    p = 4
    while not is_prime(p):
        p = generate_prime_candidate(length)
    return p

def modinv(a, m):
    g, x, y = extended_gcd(a,m)
    if g != 1:
        return None
    else:
        return x % m
    
def extended_gcd(a,b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b%a, a)
        return (g, x - (b//a) * y, y)

def generate_keypair(keysize=512):
    e = 65537

    p = generate_prime_number(keysize // 2)
    q = generate_prime_number(keysize // 2)
    while q == p:
        q = generate_prime_number(keysize // 2)
    
    n = p * q
    phi = (p-1) * (q-1)

    if gcd(e, phi) != 1:
        raise Exception('e dan phi(n) tidak relatif prima')
    
    d = modinv(e, phi)
    if d is None:
        raise Exception('Gagal menghitung modular inverse.')
    
    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key

def encrypt(pk, plaintext):
    key, n = pk
    cipher = [pow(ord(char), key, n) for char in plaintext]
    return cipher

def decrypt(pk, ciphertext):
    key, n = pk
    plain = [chr(pow(char, key, n)) for char in ciphertext]
    return ''.join(plain)