#!/usr/bin/env python3
# The Server script

# import serious stuff
import socket


# the main function
def main():
    listen_port = 1337

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((socket.gethostname(), listen_port))

    server_socket.listen()

    while True:
        received_message = ""
        print(">>", end = "")
        connection, client_address = server_socket.accept()
        
        while True:
            data = connection.recv(16)

            if data:
                received_message += data.decode()
            else:
                break

        print(received_message)
        connection.close()


# call the main function
main()
