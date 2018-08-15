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
import logging


def find_network():
    # get the config directory
    config_dir = get_config_dir()

    # look if known_network exists
    known_network_file = os.path.join(config_dir, "known_network")
    if os.path.exists(known_network_file):
        with open(known_network_file, "r"):
            network_address = known_network_file.read().rstrip()
            
    # look if network is up
    # if any of above conditions is false,
    # list all network interfaces
    # find address of each interface and loop
    # try finding hosts in each interface
    # if sucessful, store it to known_network
    pass


# get the config directory
def get_config_dir():
    # get the username
    user = os.getlogin() # debug: getlogin() might not work on all distros

    # stich the complete path
    config_dir = os.path.join("/home", user, ".config", "netdog")

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
    with open(os.path.join(config_dir, "public_key"), "r") as public_key_file:
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
    logging.info("trying to create listening socket")
    daemon_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    daemon_socket.bind(("0.0.0.0", port))
    daemon_socket.listen(5) # debug: what does this mean?

    # listen for incoming connections
    while True:
        # accept connection
        connection, client_address = daemon_socket.accept()

        # pass the connection to connection handler
        print(client_address)
        logging.info("new connection received from" + client_address)
        handle_client_connection(connection, client_address) # debug: implement threading

    # close the listen socket
    daemon_socket.close()


# find a host running project green
def find_hosts(network_address, server):
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


# check and set up essential stuff
def initialize_system(server):
    # if config directory does not exists, create it
    config_dir = get_config_dir()
    if not os.path.isdir(config_dir):
        try:
            os.mkdir(config_dir)
        except:
            # show error and exit the application
            print("error: config dir cannot be created! exiting...")
            sys.exit(1)
    
    # set up logging
    logging.basicConfig(filename = os.path.join(config_dir, "log"),
        level = logging.DEBUG)
    
    # log initial messages
    logging.info("NetDog (alpha) is starting up")
    logging.info("System passed initial checks")
    
    # if client and known_server missing, return paired as False
    if server == False:
        # debug: function to cross check known_server with current server
        if not os.path.exists(os.path.join(config_dir, "known_server")):
            logging.info("the client is not paired with a server")
            # debug: start client pairing request
            pass
