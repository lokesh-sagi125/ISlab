from cryptography.hazmat.primitives.asymmetric import rsa, dh, ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os
import secrets


class CryptoSystem:

    ### RSA Functions ###
    @staticmethod
    def generate_rsa_key_pair(key_size=2048):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def rsa_encrypt(public_key, message):
        ciphertext = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    @staticmethod
    def rsa_decrypt(private_key, ciphertext):
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    ### Diffie-Hellman Key Exchange ###
    @staticmethod
    def generate_diffie_hellman_params():
        parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        return parameters

    @staticmethod
    def generate_diffie_hellman_keys(parameters):
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def derive_shared_key(private_key, peer_public_key):
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data",
            backend=default_backend()
        ).derive(shared_key)
        return derived_key

    ### ElGamal Functions ###
    @staticmethod
    def generate_elgamal_key_pair(prime_bits=256):
        p = secrets.randbits(prime_bits) | 1  # Large prime
        g = secrets.randbelow(p - 1) + 1
        x = secrets.randbelow(p - 2) + 1      # Private key
        h = pow(g, x, p)                      # Public key
        private_key = x
        public_key = (p, g, h)
        return private_key, public_key

    @staticmethod
    def elgamal_encrypt(public_key, plaintext):
        p, g, h = public_key
        if isinstance(plaintext, bytes):
            plaintext = int.from_bytes(plaintext, byteorder='big')
        
        y = secrets.randbelow(p - 1) + 1
        c1 = pow(g, y, p)
        c2 = (plaintext * pow(h, y, p)) % p
        return c1, c2

    @staticmethod
    def elgamal_decrypt(private_key, public_key, ciphertext):
        p, g, h = public_key
        c1, c2 = ciphertext
        s = pow(c1, private_key, p)
        s_inv = pow(s, p - 2, p)  # Modular inverse
        plaintext = (c2 * s_inv) % p
        plaintext_bytes = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, byteorder='big')
        return plaintext_bytes

    ### ECC (Elliptic Curve Cryptography) Functions ###
    def generate_ecc_key_pair():
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def ecc_encrypt(public_key, message):
        # Generate an ephemeral private key for ECDH
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key)
        
        # Derive a symmetric key from the shared ECDH key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"encryption data",
            backend=default_backend()
        ).derive(shared_key)
        
        # Encrypt the message using AES with the derived symmetric key
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()

        # Return both the ephemeral public key and the ciphertext for decryption
        ephemeral_public_key = ephemeral_private_key.public_key()
        return ephemeral_public_key, iv + ciphertext

    @staticmethod
    def ecc_decrypt(private_key, ephemeral_public_key, ciphertext):
        # Recreate the shared key from the recipient's private key and sender's ephemeral public key
        shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)
        
        # Derive the same symmetric key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"encryption data",
            backend=default_backend()
        ).derive(shared_key)
        
        # Separate the IV and actual ciphertext
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        
        # Decrypt the message using AES with the derived symmetric key
        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        return plaintext

    ### AES Symmetric Encryption for General Use ###
    @staticmethod
    def generate_symmetric_key():
        return os.urandom(32)  # 256-bit key

    @staticmethod
    def symmetric_encrypt(key, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext

    @staticmethod
    def symmetric_decrypt(key, ciphertext):
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        return plaintext


# Example usage of the CryptoSystem class
if __name__ == "__main__":
    message = b"Sensitive information for encryption"

    # RSA Example
    print("RSA Example:")
    rsa_private_key, rsa_public_key = CryptoSystem.generate_rsa_key_pair()
    rsa_ciphertext = CryptoSystem.rsa_encrypt(rsa_public_key, message)
    rsa_plaintext = CryptoSystem.rsa_decrypt(rsa_private_key, rsa_ciphertext)
    print("RSA Decryption Successful:", message == rsa_plaintext)

    # Diffie-Hellman Key Exchange
    print("\nDiffie-Hellman Example:")
    dh_params = CryptoSystem.generate_diffie_hellman_params()
    private_key_a, public_key_a = CryptoSystem.generate_diffie_hellman_keys(dh_params)
    private_key_b, public_key_b = CryptoSystem.generate_diffie_hellman_keys(dh_params)
    shared_key_a = CryptoSystem.derive_shared_key(private_key_a, public_key_b)
    shared_key_b = CryptoSystem.derive_shared_key(private_key_b, public_key_a)
    print("Shared Key Match:", shared_key_a == shared_key_b)

    # ElGamal Example
    print("\nElGamal Example:")
    elgamal_private_key, elgamal_public_key = CryptoSystem.generate_elgamal_key_pair()
    elgamal_ciphertext = CryptoSystem.elgamal_encrypt(elgamal_public_key, message)
    elgamal_plaintext = CryptoSystem.elgamal_decrypt(elgamal_private_key, elgamal_public_key, elgamal_ciphertext)
    print("ElGamal Decryption Successful:", message == elgamal_plaintext)

    # ECC Example
    print("\nECC Example:")
    ecc_private_key, ecc_public_key = CryptoSystem.generate_ecc_key_pair()
    
    # Encrypt the message with ECC
    ephemeral_public_key, ecc_ciphertext = CryptoSystem.ecc_encrypt(ecc_public_key, message)
    
    # Decrypt the message with ECC
    ecc_plaintext = CryptoSystem.ecc_decrypt(ecc_private_key, ephemeral_public_key, ecc_ciphertext)
    print("ECC Decryption Successful:", message == ecc_plaintext)

    # AES Symmetric Encryption Example
    print("\nAES Symmetric Encryption Example:")
    symmetric_key = CryptoSystem.generate_symmetric_key()
    aes_ciphertext = CryptoSystem.symmetric_encrypt(symmetric_key, message)
    aes_plaintext = CryptoSystem.symmetric_decrypt(symmetric_key, aes_ciphertext)
    print("AES Decryption Successful:", message == aes_plaintext)
