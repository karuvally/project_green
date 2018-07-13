#!/usr/bin/env python3
# Project Green, daemon, alpha release
# Copyright 2018, Aswin Babu Karuvally

# import the serious stuff
import socket
import subprocess


# create socket and listen
def create_socket():
    try:
        daemon_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        daemon_socket.bind(("0.0.0.0", 1337))
        daemon_socket.listen(5) # debug

        while True:
            connection, client_address = daemon_socket.accept()
    except KeyboardInterrupt:
        print("exiting gracefully...")
    except:
        print("error: cannot bind to port 1337!")


# the main function
def main():
    # create the socket for listening
    create_socket()


# run the maain function
main()
