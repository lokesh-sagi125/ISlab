import socket
import threading
socket_server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
#host = socket.gethostname()
host = '0.0.0.0'
port = 2521
socket_server.bind((host,port))
socket_server.listen(1)

def send(client_socket):
    while True:
        msg = input('messege:')
        client_socket.send(msg.encode('utf-8'))
    
def recieve(client_socket) :
    while True:
        msgr = client_socket.recv(2048)
        msgf = msgr.decode('utf-8')
        if msgf == 'exit':
            client_socket.close()
        else:
            print(msgf)

client_socket,addr = socket_server.accept()
        
t1 = threading.Thread(target=send,args=(client_socket,))
t2 = threading.Thread(target=recieve,args=(client_socket,))

t1.start()
t2.start()