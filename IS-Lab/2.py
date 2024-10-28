# Import necessary libraries
from phe import paillier  # Paillier cryptosystem library
from collections import defaultdict

# Step 2a: Create a sample text corpus of 10 documents, each containing multiple words
documents = [
    "the cat in the hat",
    "the quick brown fox",
    "jumps over the lazy dog",
    "the fox and the hound",
    "she sells sea shells",
    "by the sea shore",
    "how much wood",
    "would a woodchuck chuck",
    "if a woodchuck could",
    "chuck wood"
]

# Generate document IDs for each document (we'll use the index as the ID)
doc_ids = list(range(len(documents)))

# Step 2b: Set up Paillier encryption
# Generate public and private keys for encryption and decryption
public_key, private_key = paillier.generate_paillier_keypair()

# Function to encrypt a single integer (for document IDs or index entries)
def encrypt_integer(value, pub_key):
    return pub_key.encrypt(value)

# Function to decrypt a single integer
def decrypt_integer(encrypted_value, priv_key):
    return priv_key.decrypt(encrypted_value)

# Step 2c: Build an encrypted inverted index
# Initialize an inverted index (dictionary) where each word maps to a list of document IDs
inverted_index = defaultdict(list)

# Populate the inverted index
for doc_id, text in enumerate(documents):
    words = text.split()
    for word in words:
        inverted_index[word].append(doc_id)

# Encrypt the inverted index
# This dictionary will store encrypted word mappings
encrypted_index = {}

for word, doc_list in inverted_index.items():
    # Encrypt each document ID in the list for the word
    encrypted_doc_list = [encrypt_integer(doc_id, public_key) for doc_id in doc_list]
    encrypted_index[word] = encrypted_doc_list

# Step 2d: Implement the search function
def search(query_word, pub_key, priv_key, encrypted_idx):
    # Encrypt the query word (Paillier cryptosystem does not support direct text encryption)
    # Therefore, we use the plain text word to search the encrypted index
    if query_word in encrypted_idx:
        # Retrieve the encrypted document list for the query word
        encrypted_doc_ids = encrypted_idx[query_word]
        
        # Decrypt each document ID in the list
        decrypted_doc_ids = [decrypt_integer(doc_id, priv_key) for doc_id in encrypted_doc_ids]
        
        return decrypted_doc_ids
    else:
        # If the word is not found in the index, return an empty list
        return []

# Test the search function
query = "wood"  # Example search term
print("Searching for the word:", query)
result_doc_ids = search(query, public_key, private_key, encrypted_index)

# Display the search results
print("Documents containing the word '{}':".format(query), result_doc_ids)
