from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
from collections import defaultdict

# Generate a random key for AES encryption
key = os.urandom(16)  # AES-128
iv = os.urandom(16)   # Initialization vector

def encrypt_aes(plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the plaintext to make it a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt_aes(ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    
    return unpadded_data.decode()

# Step 1a: Create a dataset
documents = {
    1: "the quick brown fox jumps over the lazy dog",
    2: "never gonna give you up never gonna let you down",
    3: "hello world this is a test document",
    4: "secure search engine with encrypted data",
    5: "data science is the future of technology",
    6: "python programming for data analysis",
    7: "machine learning and artificial intelligence",
    8: "the quick brown fox is clever",
    9: "data security is important for privacy",
    10: "encryption helps protect sensitive information"
}

# Step 1c: Create an inverted index
def create_inverted_index(docs):
    index = defaultdict(set)
    for doc_id, text in docs.items():
        words = text.split()
        for word in words:
            index[word].add(doc_id)
    return index

# Create the inverted index
inverted_index = create_inverted_index(documents)

# Encrypt the inverted index
encrypted_index = {encrypt_aes(word): encrypt_aes(",".join(map(str, doc_ids))) for word, doc_ids in inverted_index.items()}

# Display the encrypted index for debugging
print("Encrypted Index:")
for word, doc_ids in encrypted_index.items():
    print(f"{word.hex()}: {doc_ids.hex()}")

# Step 1d: Implement the search function
def search(query):
    encrypted_query = encrypt_aes(query)
    results = {}
    
    # Check the inverted index for the encrypted query
    for word, doc_ids_encrypted in encrypted_index.items():
        if encrypted_query == word:
            doc_ids = decrypt_aes(doc_ids_encrypted).split(",")
            results = {doc_id: documents[int(doc_id)] for doc_id in doc_ids}
            break

    return results

# Example search
query = "quick"
search_results = search(query)

# Output results
print("Search Results:")
if search_results:
    for doc_id, doc_text in search_results.items():
        print(f"Document ID {doc_id}: {doc_text}")
else:
    print("No documents found.")
