#!/usr/bin/env python3
# Client Module

# import serious stuff
import socket


# the main function
def main():
    port = 1337

    while True:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((socket.gethostname(), port))

        message = bytes(input(">"), "utf-8")
    
        client_socket.sendall(message)
        client_socket.close()


# call the main function
main()
