from cryptography.hazmat.primitives.asymmetric import rsa, dh
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
    def rsa_sign(private_key, message):
        signature = private_key.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def rsa_verify(public_key, message, signature):
        try:
            public_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    ### ElGamal Functions ###
    # @staticmethod
    # def generate_elgamal_key_pair(prime_bits=256):
    #     p = secrets.randbits(prime_bits) | 1  # Generate a large prime
    #     g = secrets.randbelow(p - 1) + 1
    #     x = secrets.randbelow(p - 2) + 1      # Private key
    #     h = pow(g, x, p)                      # Public key
    #     private_key = x
    #     public_key = (p, g, h)
    #     return private_key, public_key

    # def elgamal_encrypt(public_key, plaintext):
    #     p, g, h = public_key
    #     # Convert plaintext to integer if it’s a byte/string, to fit within the modulus
    #     if isinstance(plaintext, bytes):
    #         plaintext = int.from_bytes(plaintext, byteorder='big')
        
    #     y = secrets.randbelow(p - 1) + 1
    #     c1 = pow(g, y, p)
    #     c2 = (plaintext * pow(h, y, p)) % p
    #     return c1, c2

    # @staticmethod
    # def elgamal_decrypt(private_key, public_key, ciphertext):
    #     p, g, h = public_key
    #     c1, c2 = ciphertext
    #     s = pow(c1, private_key, p)
    #     s_inv = pow(s, p - 2, p)  # Modular inverse using Fermat’s little theorem
    #     plaintext = (c2 * s_inv) % p
    #     # Convert integer back to bytes if necessary
    #     plaintext_bytes = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, byteorder='big')
    #     return plaintext_bytes

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

    ### Schnorr-like Symmetric Encryption (using Diffie-Hellman Shared Key) ###
    @staticmethod
    def symmetric_encrypt(shared_key, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext

    @staticmethod
    def symmetric_decrypt(shared_key, ciphertext):
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        return plaintext


# Example usage of the CryptoSystem class
if __name__ == "__main__":
    # RSA Example
    print("RSA Example:")
    rsa_private_key, rsa_public_key = CryptoSystem.generate_rsa_key_pair()
    message = b"Secure message"
    rsa_signature = CryptoSystem.rsa_sign(rsa_private_key, message)
    print("RSA Signature Verified:", CryptoSystem.rsa_verify(rsa_public_key, message, rsa_signature))

    # # ElGamal Example
    # print("\nElGamal Example:")
    # elgamal_private_key, elgamal_public_key = CryptoSystem.generate_elgamal_key_pair()
    # plaintext = 123456
    # ciphertext = CryptoSystem.elgamal_encrypt(elgamal_public_key, plaintext)
    # decrypted_plaintext = CryptoSystem.elgamal_decrypt(elgamal_private_key, elgamal_public_key, ciphertext)
    # print("ElGamal Decryption Successful:", plaintext == decrypted_plaintext)

    # Diffie-Hellman Key Exchange
    print("\nDiffie-Hellman Key Exchange:")
    dh_params = CryptoSystem.generate_diffie_hellman_params()
    private_key_a, public_key_a = CryptoSystem.generate_diffie_hellman_keys(dh_params)
    private_key_b, public_key_b = CryptoSystem.generate_diffie_hellman_keys(dh_params)
    shared_key_a = CryptoSystem.derive_shared_key(private_key_a, public_key_b)
    shared_key_b = CryptoSystem.derive_shared_key(private_key_b, public_key_a)
    print("Shared Key Match:", shared_key_a == shared_key_b)

    # Schnorr-like Symmetric Encryption using Diffie-Hellman Shared Key
    print("\nSchnorr-like Symmetric Encryption:")
    plaintext_message = b"Confidential data for symmetric encryption"
    encrypted_message = CryptoSystem.symmetric_encrypt(shared_key_a, plaintext_message)
    decrypted_message = CryptoSystem.symmetric_decrypt(shared_key_b, encrypted_message)
    print("Symmetric Decryption Successful:", decrypted_message == plaintext_message)
