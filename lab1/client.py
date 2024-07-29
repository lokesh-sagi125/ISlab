import socket
import threading
client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
host = '172.16.53.52'
port = 4321
client_socket.connect((host,port))


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

        
t1 = threading.Thread(target=send,args=(client_socket,))
t2 = threading.Thread(target=recieve,args=(client_socket,))

t1.start()
t2.start()