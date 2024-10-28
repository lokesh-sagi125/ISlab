from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
from collections import defaultdict

# Utility functions for AES Encryption and Decryption
def encrypt_aes(key, plaintext):
    """Encrypts a plaintext message using AES encryption."""
    iv = os.urandom(16)  # Generate a random Initialization Vector (IV)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad plaintext to be a multiple of the block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # Encrypt data
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted  # Return IV + encrypted data for later decryption

def decrypt_aes(key, ciphertext):
    """Decrypts an AES-encrypted message."""
    iv = ciphertext[:16]  # Extract the IV from the start of the ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt data
    padded_plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()

    # Remove padding to get original plaintext
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

# Step 1a: Create a dataset
documents = [
    "this is the first document",
    "second document contains different words",
    "text data for the third document",
    "another document to search",
    "encryption and decryption example",
    "searchable encryption systems",
    "systems for secure document search",
    "secure search with encrypted index",
    "index creation for secure search",
    "implementing secure searchable encryption"
]

# Step 1b: Generate a random key for AES encryption (must be 16, 24, or 32 bytes)
aes_key = os.urandom(32)  # 32 bytes key for AES-256 encryption

# Step 1c: Create an inverted index and encrypt it
inverted_index = defaultdict(list)

# Populate the inverted index: Map each word to document IDs containing it
for doc_id, text in enumerate(documents):
    for word in text.split():
        inverted_index[word].append(doc_id)

# Encrypt the inverted index
encrypted_index = {}
for word, doc_ids in inverted_index.items():
    encrypted_word = encrypt_aes(aes_key, word)  # Encrypt each word
    encrypted_doc_ids = [encrypt_aes(aes_key, str(doc_id)) for doc_id in doc_ids]  # Encrypt document IDs
    encrypted_index[encrypted_word] = encrypted_doc_ids  # Store encrypted mappings

# Step 1d: Implement the search function
def search_encrypted_index(query):
    """Searches the encrypted index for the encrypted query and retrieves document IDs."""
    # Encrypt the search query
    encrypted_query = encrypt_aes(aes_key, query)
    
    # Search for encrypted query in the encrypted index
    if encrypted_query in encrypted_index:
        encrypted_doc_ids = encrypted_index[encrypted_query]  # Retrieve encrypted doc IDs
        # Decrypt document IDs to retrieve original IDs
        doc_ids = [int(decrypt_aes(aes_key, enc_id)) for enc_id in encrypted_doc_ids]
        # Display the corresponding documents
        results = [documents[doc_id] for doc_id in doc_ids]
        return results
    else:
        return ["No matching documents found"]

# Example search
query = "secure"  # Search for documents containing the word "secure"
results = search_encrypted_index(query)

# Display search results
print("Search results for query '{}':".format(query))
for result in results:
    print(result)
