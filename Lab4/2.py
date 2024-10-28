import random
import logging
import time
import hashlib
from typing import Tuple

# Configure logging to display information on key management operations
logging.basicConfig(level=logging.INFO)

# Prime generation and Rabin cryptosystem functions
def generate_large_prime(bits: int) -> int:
    """Generate a large prime number of specified bit length.

    Args:
        bits (int): The desired bit length of the prime number.

    Returns:
        int: A large prime number.
    """
    while True:
        # Generate a random number of approximately 'bits' size
        num = random.getrandbits(bits)
        # Check if the generated number is prime
        if is_prime(num):
            return num

def is_prime(n: int) -> bool:
    """Check if a number is prime using a simple primality test.

    Args:
        n (int): The number to test for primality.

    Returns:
        bool: True if the number is prime, False otherwise.
    """
    if n <= 1:
        return False
    # Check divisibility from 2 up to the square root of n
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_rabin_keypair(bits: int = 1024) -> Tuple[int, Tuple[int, int]]:
    """Generate a Rabin cryptosystem key pair.

    Args:
        bits (int): The total bit length of the key pair.

    Returns:
        Tuple[int, Tuple[int, int]]: A tuple containing the public key (N) and 
                                     the private key (p, q).
    """
    # Generate two large prime numbers, p and q
    p = generate_large_prime(bits // 2)
    q = generate_large_prime(bits // 2)
    # The public key N is the product of p and q
    N = p * q
    # Return the public key (N) and the private key (p, q)
    return N, (p, q)

class KeyManagementService:
    """Centralized key management service for hospitals and clinics."""
    
    def __init__(self):
        # Dictionary to store keys for each facility by facility ID
        self.keys = {}
        # List to log all key management operations for auditing
        self.logs = []

    def generate_keypair(self, facility_id: str, bits: int = 1024) -> int:
        """Generate a Rabin key pair for a healthcare facility.

        Args:
            facility_id (str): Unique ID for the facility (e.g., hospital or clinic).
            bits (int): Bit length of the key to generate.

        Returns:
            int: The public key (N) for distribution to the facility.
        """
        # Generate a new key pair using the Rabin cryptosystem
        public_key, private_key = generate_rabin_keypair(bits)
        # Store the key pair securely, keyed by facility_id
        self.keys[facility_id] = (public_key, private_key)
        # Log the key generation action
        self.logs.append(f"Generated key for {facility_id}")
        logging.info(f"Key generated for {facility_id}")
        # Return only the public key for secure distribution
        return public_key

    def distribute_key(self, facility_id: str) -> int:
        """Simulated API function to securely distribute the public key to a facility.

        Args:
            facility_id (str): Unique ID for the facility requesting the key.

        Returns:
            int: The public key for the facility.
        """
        # Check if the facility has an existing key
        if facility_id in self.keys:
            # Return the public key only
            return self.keys[facility_id][0]
        else:
            raise ValueError("Facility not registered.")

    def revoke_key(self, facility_id: str):
        """Revoke the keys of a given facility, removing access.

        Args:
            facility_id (str): Unique ID for the facility whose key is revoked.
        """
        # Check if the facility has a registered key
        if facility_id in self.keys:
            # Remove the key from storage
            del self.keys[facility_id]
            # Log the key revocation action
            self.logs.append(f"Revoked key for {facility_id}")
            logging.info(f"Revoked key for {facility_id}")
        else:
            raise ValueError("Facility ID not found.")

    def renew_keys(self, interval_months: int = 12):
        """Renew keys for all facilities at a regular interval to maintain security.

        Args:
            interval_months (int): Renewal interval in months.
        """
        # Get the current time (for logging)
        current_time = time.time()
        # Renew keys for all facilities
        for facility_id in self.keys:
            # Generate a new key pair and update the facility's stored key
            self.generate_keypair(facility_id)
            # Log the key renewal event with a timestamp
            self.logs.append(f"Renewed key for {facility_id} at {current_time}")
            logging.info(f"Renewed key for {facility_id}")

    def secure_store_key(self, key_data: str) -> str:
        """Simulate secure storage by hashing private key data.

        Args:
            key_data (str): The private key data to store securely.

        Returns:
            str: A secure hash of the key data for storage.
        """
        # Hash the key data using SHA-256 for secure storage
        secure_hash = hashlib.sha256(key_data.encode()).hexdigest()
        return secure_hash

    def audit_log(self):
        """Print the log of all key management operations for auditing purposes."""
        logging.info("Audit Log:")
        for entry in self.logs:
            print(entry)

# Example usage of the Key Management Service
if __name__ == "__main__":
    # Create an instance of the KeyManagementService
    kms = KeyManagementService()

    # Generate and distribute keys for a healthcare facility
    facility_id = "Hospital_A"
    public_key = kms.generate_keypair(facility_id)
    logging.info(f"Public key for {facility_id}: {public_key}")

    # Distribute the key securely to the facility
    try:
        distributed_key = kms.distribute_key(facility_id)
        logging.info(f"Distributed key for {facility_id}: {distributed_key}")
    except ValueError as e:
        logging.error(e)

    # Revoke the facility's key if needed
    kms.revoke_key(facility_id)

    # Renew all keys periodically (simulating a 12-month renewal policy)
    kms.renew_keys(interval_months=12)

    # Securely store the private key data (demonstration)
    private_key_data = f"{kms.keys[facility_id][1]}" if facility_id in kms.keys else "SamplePrivateKey"
    secure_key_storage = kms.secure_store_key(private_key_data)
    logging.info(f"Securely stored key hash for {facility_id}: {secure_key_storage}")

    # Output audit log
    kms.audit_log()
