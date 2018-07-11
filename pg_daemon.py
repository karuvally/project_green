#!/usr/bin/env python3
# Project Green, Daemon module
# Copyright 2018, Aswin Babu Karuvally

# TODO
# user defined port option
# log stuff

# import the serious stuff
import socket


# create socket and listen
def create_socket():
    daemon_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    daemon_socket.bind((socket.gethostname(), 1337))
    daemon_socket.listen(5) # debug

    while True:
        connection, client_address = daemon_socket.accept()


# the main function
def main():
    create_socket()
