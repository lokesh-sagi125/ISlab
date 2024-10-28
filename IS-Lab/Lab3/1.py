from sympy import mod_inverse

# RSA parameters (using larger primes for practicality)
p = 61
q = 53
n = p * q
phi_n = (p - 1) * (q - 1)
def gcd(p, q):
    # Use Euclid's algorithm to find the GCD.
    while q != 0:
        p, q = q, p % q
    return p

def coprime(nm):
    for i in range(2,nm):
        if gcd(i, nm) == 1:
            return i
    return None
e=coprime(phi_n)
# Compute private key d
d = mod_inverse(e,phi_n)
print(d)
# RSA encryption function
def rsa_encrypt(message, n, e):
    encmsg=[]
    for char in message:
        encmsg.append((pow(ord(char),e))%n)
        
    return encmsg

# RSA decryption function
def rsa_decrypt(encrypted_int, n, d):
    decmsg=""
    for i in encrypted_int:
        decmsg += chr(pow(i,d)%n)
    
    return decmsg

# Example message
message = "Asymmetric Encryption"

# Encrypt the message
encrypted_message = rsa_encrypt(message, n, e)
print("Encrypted message (integer):", encrypted_message)

# Decrypt the message
decrypted_message = rsa_decrypt(encrypted_message, n, d)
print("Decrypted message:", decrypted_message)
