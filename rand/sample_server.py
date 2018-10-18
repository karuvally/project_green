#!/usr/bin/env python3

# the serious stuff
import socket

server_socket = socket.socket()
server_socket.bind(("0.0.0.0", 1337))
server_socket.listen(10)

while True:
    (client_socket, client_address) = server_socket.accept()
    client_input = client_socket.recv(1024)
    client_socket.close()

server_socket.close()
