#!/usr/bin/env python3
# Project Green Library, alpha release
# Copyright 2018, Aswin Babu Karuvally

# import essential libraries
import os
import sys
import time
import socket
from Crypto.PublicKey import RSA


# generate public-private key pair
def generate_keys():
    key = RSA.generate(1024)
    
    public_key = key.publickey().exportKey()
    private_key = key.exportKey()

    return({
        "public_key": public_key,
        "private_key": private_key
    })


# handle the incoming data
def receive_data(connection, client_address):
    data = ""

    while True:
        data_buffer = connection.recv(16)

        if data_buffer:
            data += data_buffer.decode()
        else:
            break
    
    connection.close()
    return data


# create client socket and send data
def send_data(data, destination, port):
    data = bytes(data, "utf-8")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((destination, port))
    
    client_socket.sendall(data)
    client_socket.close()


# create server socket and listen
def create_server_socket(port):
    daemon_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    daemon_socket.bind(("0.0.0.0", port))
    daemon_socket.listen(5) # debug

    while True:
        connection, client_address = daemon_socket.accept()
        data = receive_data(connection, client_address) # implement threading

    daemon_socket.close()
    connection.close()


# check and set up essential stuff
def initialize_system(config_dir):
    if not os.path.isdir(config_dir):
        try:
            os.mkdir(config_dir)
        except:
            print("error: config dir cannot be created! exiting...")
            sys.exit(1)


#writes data to the log file
def write_to_log (matter, config_dir):
    log_path = os.path.join(config_dir, "log")
    try:
        log_file = open (log_path, "a")

        log_file.write (time.strftime("[%d-%b-%Y %H:%M:%S] "))
        log_file.write (matter + "\n")
        log_file.close()
    except:
        print("error: cannot write to log! exiting...")
        sys.exit(1)

