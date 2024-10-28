import socket
import hashlib


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

data = b"Hello, this is a test message."

client_socket.sendall(data)

received_hash  = client_socket.recv(2048)


received_hash = received_hash.decode()

computed_hash = hashlib.sha256(data).hexdigest()

if computed_hash == received_hash:
    print("Data integrity verified: Hashes match! 😊")
else:
    print("Data integrity check failed: Hashes do not match!")

client_socket.close()