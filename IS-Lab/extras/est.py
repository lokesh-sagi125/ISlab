from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os
import base64
from typing import Dict

# Key management - stores keys and facilitates key distribution and revocation
# Key management - stores keys and facilitates key distribution and revocation
class KeyManagementSystem:
    def __init__(self):
        self.keys = {}

    def generate_rsa_keys(self, subsystem_name: str):
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Store keys
        self.keys[subsystem_name] = {
            "private_key": private_key,
            "public_key": public_key
        }
        return private_key, public_key

    def get_public_key(self, subsystem_name: str):
        return self.keys[subsystem_name]["public_key"]

    def revoke_key(self, subsystem_name: str):
        if subsystem_name in self.keys:
            del self.keys[subsystem_name]
            return True
        return False


# Secure communication setup - RSA encryption and Diffie-Hellman key exchange
class SecureCommunication:
    def __init__(self, key_management_system: KeyManagementSystem):
        self.kms = key_management_system

    def rsa_encrypt(self, public_key, message: bytes):
        encrypted_message = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_message

    def rsa_decrypt(self, private_key, encrypted_message: bytes):
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message

    def generate_diffie_hellman_parameters(self):
        # Generate DH parameters
        return dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

    def generate_diffie_hellman_keys(self, parameters):
        # Generate DH private and public keys
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key

    def diffie_hellman_shared_key(self, private_key, peer_public_key):
        # Derive shared key
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure communication',
            backend=default_backend()
        ).derive(shared_key)
        return derived_key


# Mock subsystems to test secure communication and key management
class Subsystem:
    def __init__(self, name: str, kms: KeyManagementSystem, secure_comm: SecureCommunication, dh_params):
        self.name = name
        self.kms = kms
        self.secure_comm = secure_comm
        self.private_key, self.public_key = kms.generate_rsa_keys(name)
        self.dh_private_key, self.dh_public_key = secure_comm.generate_diffie_hellman_keys(dh_params)

    def send_secure_message(self, recipient: 'Subsystem', message: str):
        # RSA encrypt message using recipient's public key
        recipient_public_key = self.kms.get_public_key(recipient.name)
        encrypted_message = self.secure_comm.rsa_encrypt(recipient_public_key, message.encode())
        print(f"Encrypted message sent from {self.name} to {recipient.name}: {base64.b64encode(encrypted_message).decode()}")
        
        # DH key exchange
        shared_key = self.secure_comm.diffie_hellman_shared_key(self.dh_private_key, recipient.dh_public_key)
        print(f"{self.name} and {recipient.name} derived shared DH key: {base64.b64encode(shared_key).decode()}")
        
        # Recipient decrypts the message
        decrypted_message = recipient.receive_secure_message(self, encrypted_message)
        print(f"{recipient.name} received and decrypted message: {decrypted_message}")

    def receive_secure_message(self, sender: 'Subsystem', encrypted_message: bytes):
        decrypted_message = self.secure_comm.rsa_decrypt(self.private_key, encrypted_message)
        return decrypted_message.decode()


# Main execution to simulate secure communication between subsystems
if __name__ == "__main__":
    kms = KeyManagementSystem()
    secure_comm = SecureCommunication(kms)

    # Generate a single set of DH parameters for all subsystems to share
    shared_dh_params = secure_comm.generate_diffie_hellman_parameters()

    # Create subsystems A, B, and C with the shared DH parameters
    subsystem_a = Subsystem("Finance System (A)", kms, secure_comm, shared_dh_params)
    subsystem_b = Subsystem("HR System (B)", kms, secure_comm, shared_dh_params)
    subsystem_c = Subsystem("Supply Chain Management (C)", kms, secure_comm, shared_dh_params)

    # Send secure messages between subsystems
    subsystem_a.send_secure_message(subsystem_b, "Financial Report Q3")
    subsystem_b.send_secure_message(subsystem_c, "Employee Contract")
    subsystem_c.send_secure_message(subsystem_a, "Procurement Order")

    # Revoking a key
    kms.revoke_key("HR System (B)")
    print(f"Keys after revocation: {list(kms.keys.keys())}")
