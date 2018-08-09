#!/usr/bin/env python3
# libgreen, alpha release
# Copyright 2018, Aswin Babu Karuvally

# import essential libraries
import os
import sys
import time
import socket
from Crypto.PublicKey import RSA
import ipaddress
from subprocess import Popen, PIPE


# get the config directory
def get_config_dir():
    # get the username
    user = os.getlogin() # debug: getlogin() might not work on all distros

    # stich the complete path
    config_dir = os.path.join("/home", user, ".netdog")

    return config_dir


# accept pairing request from client
def accept_pairing_request(payload):
    pass
    # separate public_key and hostname
    splitted_payload = payload.split(",", 1)

    # store the public_key, hostname pair to text file
    config_dir = get_config_dir()
    with open(os.path.join(config_dir, "known_hosts"), "a") as known_hosts_file:
        known_hosts_file.write(splitted_payload[1] + "," +
            splitted_payload[2] + "\n")

    # get public_key of the server
    with open(os.path.join(config_dir, "pub_key"), "r") as public_key_file:
        public_key = public_key_file.read().rstrip()

    # return the public key
    return public_key

# handle data and act accordingly
def handle_data(command, payload):
    # handle the pairing request
    if command == "pair":
        return_data = accept_pairing_request(separated_data[1])

        # implement rest of the commands

        return return_data


# handle newly created connection, debug: implement threading
def handle_client_connection(connection, client_address):
    data = receive_data(connection)
    # separate command and payload
    separated_data = data.split(",", 1)

    # reply client with returned data
    if return_data:
        connection.sendall(return_data)

    # close the connection :D
    connection.close()


# create server socket and listen
def create_new_listen_socket(port):
    # create the socket
    daemon_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    daemon_socket.bind(("0.0.0.0", port))
    daemon_socket.listen(5) # debug: what does this mean?

    # listen for incoming connections
    while True:
        # accept connection
        connection, client_address = daemon_socket.accept()

        # pass the connection to connection handler
        handle_client_connection(connection, client_address) # debug: implement threading

    # close the listen socket
    daemon_socket.close()


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
    # set the size for the generated key
    key = RSA.generate(1024)
    
    # create public-private key pair
    public_key = key.publickey().exportKey()
    private_key = key.exportKey()

    # return key pair as dictionary
    return({
        "public_key": public_key,
        "private_key": private_key
    })


# handle the incoming data
def receive_data(connection):
    # an empty string for storing data
    data = ""

    while True:
        # receive data with buffer size as 16 bytes
        data_buffer = connection.recv(16)

        # continue if data_buffer is not None
        if data_buffer:
            # convert received data to unicode
            data += data_buffer.decode()
        else:
            break

    return data


# create client socket and send data, debug: function might be removed
def send_data(data, destination, port):
    data = bytes(data, "utf-8")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((destination, port))
    
    client_socket.sendall(data)
    client_socket.close()


# check and set up essential stuff
def initialize_system(config_dir):
    # if config directory does not exists, create it
    if not os.path.isdir(config_dir):
        try:
            os.mkdir(config_dir)
        except:
            # show error and exit the application
            print("error: config dir cannot be created! exiting...")
            sys.exit(1)


#writes data to the log file, debug: replace with python inbuilt logging
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
