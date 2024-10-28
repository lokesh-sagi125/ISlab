from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class KeyManagement:
    def __init__(self):
        # Dictionary to store keys (optional, can be used for key management purposes)
        self.keys = {}

    def generate_rsa_keypair(self):
        # Generates an RSA key pair (private and public keys)
        # RSA is used for secure communication by encrypting and decrypting messages
        private_key = rsa.generate_private_key(
            public_exponent=65537,  # Common public exponent
            key_size=2048,          # Key size in bits, 2048 is standard for security
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt_with_rsa(self, public_key, message):
        # Encrypts a message using the provided RSA public key
        # Uses OAEP padding to ensure secure encryption
        return public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask generation function
                algorithm=hashes.SHA256(),                   # Hashing algorithm
                label=None
            )
        )

    def decrypt_with_rsa(self, private_key, encrypted_message):
        # Decrypts an encrypted message using the provided RSA private key
        return private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Same padding settings as encryption
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def generate_dh_parameters(self):
        # Generates Diffie-Hellman parameters for creating key pairs
        # DH parameters allow two parties to establish a shared secret key over an insecure channel
        parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        return parameters

    def generate_dh_keypair(self, parameters):
        # Generates a Diffie-Hellman private and public key pair using the provided parameters
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key

    def derive_shared_key(self, private_key, peer_public_key):
        # Derives a shared secret key using Diffie-Hellman private key and the peer's public key
        # The shared key is then used to create a symmetric key for secure communication
        shared_key = private_key.exchange(peer_public_key)
        # Use HKDF (HMAC-based Key Derivation Function) to derive a secure key from the shared secret
        derived_key = HKDF(
            algorithm=hashes.SHA256(),   # Hash function for the key derivation
            length=32,                   # Length of the derived key in bytes
            salt=None,                   # Optional salt value; using None for simplicity
            info=b'secure communication',# Contextual information for key derivation
            backend=default_backend()
        ).derive(shared_key)
        return derived_key

class SecureCommunication:
    def __init__(self, key):
        # Initializes with a symmetric key for encrypting/decrypting messages
        self.key = key

    def encrypt_message(self, plaintext):
        # Encrypts a plaintext message using AES (Advanced Encryption Standard)
        # AES is a symmetric encryption algorithm, meaning the same key is used for encryption and decryption
        iv = os.urandom(16)  # Generates a random Initialization Vector (IV) for encryption
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        # Returns the IV concatenated with the encrypted message
        return iv + encryptor.update(plaintext) + encryptor.finalize()

    def decrypt_message(self, encrypted_message):
        # Decrypts a message that was encrypted with the same symmetric key
        # The first 16 bytes of the encrypted_message are the IV
        iv = encrypted_message[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        # Returns the decrypted plaintext
        return decryptor.update(encrypted_message[16:]) + decryptor.finalize()

# Example Usage
key_mgmt = KeyManagement()

# RSA Encryption Example
private_key, public_key = key_mgmt.generate_rsa_keypair()
message = b'Secure message between systems.'
encrypted_message = key_mgmt.encrypt_with_rsa(public_key, message)
print("Encrypted Message:", encrypted_message)
decrypted_message = key_mgmt.decrypt_with_rsa(private_key, encrypted_message)
print("Decrypted Message:", decrypted_message)

# Diffie-Hellman Key Exchange Example
parameters = key_mgmt.generate_dh_parameters()
private_key1, public_key1 = key_mgmt.generate_dh_keypair(parameters)
private_key2, public_key2 = key_mgmt.generate_dh_keypair(parameters)

# Derive shared keys on both sides
shared_key1 = key_mgmt.derive_shared_key(private_key1, public_key2)
shared_key2 = key_mgmt.derive_shared_key(private_key2, public_key1)

# Ensure that the derived shared keys match
assert shared_key1 == shared_key2

# Secure Communication using the derived shared key
secure_comm = SecureCommunication(shared_key1)
secure_encrypted_message = secure_comm.encrypt_message(b'Important secure document content')
print("Secure Encrypted Message:", secure_encrypted_message)
secure_decrypted_message = secure_comm.decrypt_message(secure_encrypted_message)
print("Secure Decrypted Message:", secure_decrypted_message)
