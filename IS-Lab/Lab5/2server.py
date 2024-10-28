import socket
import hashlib

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(1)

print("Server is on")
conn,addr=server_socket.accept()
print('Server Connected')

data = conn.recv(1024)


data_hash = hashlib.sha256(data).hexdigest()

conn.send(data_hash.encode())

conn.close()
