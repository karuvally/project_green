#!/usr/bin/env python3
# Project Green Library, alpha release
# Copyright 2018, Aswin Babu Karuvally

# import essential libraries
import os
import sys
import time
import socket
from Crypto.PublicKey import RSA
import ipaddress
from subprocess import Popen, PIPE


# act according to the data
def handle_data(command, payload):
    pass
    # pass payload to appropriate functions
    # return output data from functions


# handle newly created connection, debug: implement threading
def handle_connection(connection, client_address):
    data = receive_data(connection)
    separated_data = data.split(",", 1)
    
    return_data = handle_data(separated_data[0], separated_data[1])
    if return_data:
        pass
        # send data back to the client
        
    # end the connection?


# create server socket and listen
def create_new_listen_socket(port):
    daemon_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    daemon_socket.bind(("0.0.0.0", port))
    daemon_socket.listen(5) # debug: what does this mean?

    while True:
        connection, client_address = daemon_socket.accept()
        handle_connection(connection, client_address) # debug: implement threading

    daemon_socket.close()
    connection.close()


# enable pairing mode on the server
def start_pair_on_server(public_key):
    pass
    # create server socket
    # if client connects, return server-public key
    # accept client-public key
    # close the connection


# find a host running project green
def find_hosts(network_address, server = False):
    # server listens on port 1994, clients on 1337
    if server == True:
        port = 1994
    else:
        port = 1337

    host_list = []
    network = ipaddress.ip_network(network_address + "/24")

    for ip_address in network.hosts():
        # try pinging each host
        ping = Popen(["ping", "-c", "1", str(ip_address)], stdout = PIPE)
        ping_out = ping.communicate()[0]
        return_code = ping.returncode

        # host is up if return_code is 0
        if return_code == 0:
            # check if specified ports are open on host
            connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            port_status = connection.connect_ex((str(ip_address), port))

            # port is open if port_status is 0
            if port_status == 0:
                host_list.append(ip_address)
                if server == True:
                    break

    return host_list


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
def receive_data(connection):
    data = ""

    while True:
        data_buffer = connection.recv(16)

        if data_buffer:
            data += data_buffer.decode()
        else:
            break

    return data


# create client socket and send data
def send_data(data, destination, port):
    data = bytes(data, "utf-8")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((destination, port))
    
    client_socket.sendall(data)
    client_socket.close()


# create server socket and listen, debug: might be removed
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

