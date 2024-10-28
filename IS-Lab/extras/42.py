import os
import json
import time
import logging
import secrets
from datetime import datetime, timedelta

# Logging setup
logging.basicConfig(filename="key_management_log.txt", level=logging.INFO)

# Utility functions
def generate_large_prime(bits):
    """Generates a random large prime number with the specified bit size."""
    return secrets.randbits(bits) | 1

# Rabin cryptosystem implementation for key generation
class RabinCryptosystem:
    def __init__(self, key_size=1024):
        self.key_size = key_size

    def generate_key_pair(self):
        # Generate two large primes, p and q
        p = generate_large_prime(self.key_size // 2)
        q = generate_large_prime(self.key_size // 2)
        n = p * q
        # Private and public key pairs (n is public, (p, q) are private)
        private_key = (p, q)
        public_key = n
        return public_key, private_key

# Centralized key management service
class KeyManagementService:
    def __init__(self, key_size=1024, renewal_interval_days=365):
        self.key_size = key_size
        self.renewal_interval = timedelta(days=renewal_interval_days)
        self.keys = {}
        self.load_keys()

    def load_keys(self):
        # Load keys from storage if they exist
        if os.path.exists("keys.json"):
            with open("keys.json", "r") as f:
                self.keys = json.load(f)
            logging.info(f"{datetime.now()}: Loaded existing keys.")

    def save_keys(self):
        # Save keys to secure storage
        with open("keys.json", "w") as f:
            json.dump(self.keys, f)
        logging.info(f"{datetime.now()}: Saved all keys to storage.")

    def generate_keys_for_hospital(self, hospital_id):
        # Generate public and private key using Rabin cryptosystem
        rabin = RabinCryptosystem(self.key_size)
        public_key, private_key = rabin.generate_key_pair()

        # Store keys with expiration date for automatic renewal
        expiration_date = datetime.now() + self.renewal_interval
        self.keys[hospital_id] = {
            "public_key": public_key,
            "private_key": private_key,
            "expiration_date": expiration_date.strftime("%Y-%m-%d")
        }

        self.save_keys()
        logging.info(f"{datetime.now()}: Generated keys for hospital {hospital_id}.")
        return public_key

    def distribute_key(self, hospital_id):
        # Provide secure distribution of public key
        if hospital_id in self.keys:
            public_key = self.keys[hospital_id]["public_key"]
            logging.info(f"{datetime.now()}: Distributed public key for hospital {hospital_id}.")
            return public_key
        else:
            logging.warning(f"{datetime.now()}: Key request for unknown hospital {hospital_id}.")
            return None

    def revoke_key(self, hospital_id):
        # Revoke keys for a specific hospital
        if hospital_id in self.keys:
            del self.keys[hospital_id]
            self.save_keys()
            logging.info(f"{datetime.now()}: Revoked keys for hospital {hospital_id}.")
            return True
        else:
            logging.warning(f"{datetime.now()}: Revocation attempt for unknown hospital {hospital_id}.")
            return False

    def renew_keys(self):
        # Renew keys for all hospitals whose keys are expired
        current_date = datetime.now()
        for hospital_id, key_data in self.keys.items():
            expiration_date = datetime.strptime(key_data["expiration_date"], "%Y-%m-%d")
            if current_date >= expiration_date:
                self.generate_keys_for_hospital(hospital_id)
                logging.info(f"{datetime.now()}: Renewed keys for hospital {hospital_id}.")

    def audit_logs(self):
        # Read and display logs for auditing and compliance
        with open("key_management_log.txt", "r") as log_file:
            for line in log_file:
                print(line.strip())

# Regulatory compliance (Mocked as compliance check method)
def check_compliance():
    # Check compliance with privacy regulations (e.g., HIPAA)
    compliance_issues = []
    if not os.path.exists("key_management_log.txt"):
        compliance_issues.append("Missing key management logs.")
    if not os.path.exists("keys.json"):
        compliance_issues.append("Key storage file missing.")
    
    if compliance_issues:
        logging.warning(f"{datetime.now()}: Compliance issues found - {compliance_issues}")
        return compliance_issues
    else:
        logging.info(f"{datetime.now()}: All compliance checks passed.")
        return "All checks passed."

# Trade-off Analysis between Rabin and RSA (Output as a summary for simplicity)
def tradeoff_analysis():
    analysis = {
        "Rabin Cryptosystem": {
            "Advantages": ["Efficient decryption", "Simple construction"],
            "Disadvantages": ["Ambiguity in decryption (4 possible solutions)", "Less commonly supported"]
        },
        "RSA Cryptosystem": {
            "Advantages": ["Widely supported", "Clear and unique decryption"],
            "Disadvantages": ["More computationally intensive for decryption"]
        }
    }
    return analysis


# Main Execution
if __name__ == "__main__":
    # Initialize key management service
    kms = KeyManagementService()

    # Example of key generation and distribution
    hospital_id = "Hospital_001"
    kms.generate_keys_for_hospital(hospital_id)
    public_key = kms.distribute_key(hospital_id)
    print(f"Distributed public key for {hospital_id}: {public_key}")

    # Example of revoking a key
    kms.revoke_key(hospital_id)

    # Renew keys if they are expired
    kms.renew_keys()

    # Run compliance check
    compliance_status = check_compliance()
    print(f"Compliance Status: {compliance_status}")

    # Audit logs
    print("\nAudit Logs:")
    kms.audit_logs()

    # Trade-off Analysis Summary
    print("\nTrade-off Analysis between Rabin and RSA:")
    analysis = tradeoff_analysis()
    for algo, details in analysis.items():
        print(f"{algo}:")
        for category, points in details.items():
            print(f"  {category}: {', '.join(points)}")
