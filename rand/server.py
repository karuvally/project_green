#!/usr/bin/env python3
# The Server script

# import serious stuff
import socket
import subprocess


# shutdown the system
def poweroff():
    subprocess.run(["systemctl", "poweroff"])


# the main function
def main():
    listen_port = 1337

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", listen_port))

    server_socket.listen()

    while True:
        received_message = ""
        print(">>", end = "")
        connection, client_address = server_socket.accept()

        print(client_address)
        print(dir(client_address))
        
        while True:
            data = connection.recv(16)

            if data:
                received_message += data.decode()
            else:
                break

        connection.close()
        print(received_message)

        if received_message == "halt":
            poweroff()


# call the main function
main()
