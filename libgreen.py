#!/usr/bin/env python3
# libgreen, alpha release
# Copyright 2018, Aswin Babu Karuvally

# import essential libraries
import os
import pwd
import sys
import time
import socket
import ipaddress
import logging
import netifaces
from Crypto.PublicKey import RSA
from subprocess import Popen, PIPE


# load the list of nodes on the network
def load_nodes(server = False):
    # essential varilables
    config_dir = get_config_dir()
    known_server_file = os.path.join(config_dir, "known_server")

    # if server is false, look if known_server exist
    if server == False:
        if os.path.exist(known_server_file)
            # load known_server
        else:
            # else, look if known_clients exist
    # load known_clients
    # return stuff


# try to load public / private keys, debug: refactor ASAP!
def load_keys(key_type):
    # essential varilables
    keys = {}

    # load public key, if it exists
    public_key_path = os.path.join(config_dir, "public_key")
    private_key_path = os.path.join(config_dir, "private_key")

    if key_type == "public" or "both":
        if os.path.exists(public_key_path):
            logging.info("loading public key")
            with open(public_key_path, "r") as public_key_file:
                public_key = public_key_file.read().rstrip()
                keys.append({"public_key": public_key})
    
    if key_type == "private" or "both":
        if os.path.exists(private_key_path):
            logging.info("loading private key")
            with open(private_key_path, "r") as private_key_file:
                public_key = private_key_file.read().rstrip()
                keys.append({"private_key": private_key})

    return keys


# send request to server for pairing
def request_to_pair(network_address):
    # get configuration directory
    config_dir = get_config_dir()

    # find server
    logging.info("finding server")
    server = find_hosts(network_address, mode = "server")

    # get the public key
    public_key = load_keys("public")["public_key"]

    # get the hostname of the machine
    hostname = socket.gethostname()

    # load known server info
    server_address = load_nodes()

    # send pairing request
    logging.info("sending pairing request")


    # store server details in known_server
    pass


# ping ip address and return status
def ping_address(ip_address, broadcast = False):
    if broadcast == True:
        logging.info("checking if network " + str(ip_address) + " is up")
        ping = Popen(["ping", "-b", "-c", "1", str(ip_address)], stdout = PIPE)
    else:
        logging.info("checking if node " + str(ip_address) + " is up")
        ping = Popen(["ping", "-c", "1", str(ip_address)], stdout = PIPE)
    ping_out = ping.communicate()[0]
    return_code = ping.returncode


# retrieve network info from known_network
def retrieve_network_info():
    # essential variables
    config_dir = get_config_dir()
    network_address
    network_status = 0
    interface = None
    network_address = None

    # look if known_network exists
    known_network_file_path = os.path.join(config_dir, "known_network")
    if os.path.exists(known_network_file_path):
        logging.info("using known network")
        with open(known_network_file_path, "r") as known_network_file:
            network_info = known_network_file.read().rstrip().split(",")
            interface = network_info[0]
            network_address = network_info[1]

        # look if network is up, network is up if network_status == 0
        network_status = ping_address(network_address[1], broadcast = True)
    else:
        logging.info("no known network exists")
    
    return ({
        "interface": interface,
        "network_address": network_address,
        "network_status": network_status
    })


def find_network(server = False):
    # essential variables
    host_list = None

    if server == True:
        available_interfaces = netifaces.interfaces()
        print("choose network interface")
        
        for i in range(0, len(available_interfaces)):
            address_dict = netifaces.ifaddresses(available_interfaces[i])
            network_address = address_dict[netifaces.AF_INET][0]["addr"]
            print(i+1 + ") " + available_interfaces[i] + ": " + network_address)

        user_choice = int(input(">")) - 1
        interface = available_interfaces[user_choice]
        network_address = address_dict[netifaces.AF_INET][user_choice]["addr"]
        
        logging.info("interface: " + interface + " with address: " +
        network_address + " choosen by user")

    else:
        # loop through interfaces
        for interface in netifaces.interfaces():
            # find address of each interface
            address_dict = netifaces.ifaddresses(interface)
            network_address = address_dict[netifaces.AF_INET][0]["addr"]

            # if hosts can be found, set current network as default
            host_list = find_hosts(network_address, mode = "both")

            # debug: anyway to make this more elegant?
            if host_list:
                logging.info("network: " + network_address + " found")

    # debug: future fix, move this block outside the function
    if host_list or server == True:
        with open(known_network_file_path, "w") as known_network_file:
            known_network_file.write(interface + "," + network_address)
    
    # return network address to calling function
    return network_address


# get the config directory
def get_config_dir():
    # get the username
    user = pwd.getpwuid(os.getuid())[0]

    # stich the complete path
    config_dir = os.path.join("/home", user, ".config", "netdog")

    return config_dir


# accept pairing request from client
def accept_pairing_request(payload):
    logging.info("pairing request received")
    # separate public_key and hostname
    splitted_payload = payload.split(",", 1)

    # store the public_key, hostname pair to text file
    logging.info("storing public key and ID of the client")
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
def find_hosts(network_address, mode):
    # server listens on port 1337, clients on 1994
    if mode == "server":
        logging.info("scanning for server")
        port_list = [1337]
    elif mode == "client":
        logging.info("scanning for clients")
        port_list = [1994]
    elif mode == "both":
        logging.info("scanning for nodes")
        port_list = [1337, 1994]

    host_list = []
    network = ipaddress.ip_network(network_address + "/24")

    # try pinging each host
    for ip_address in network.hosts():
        return_code = ping_address(ip_address)

        # host is up if return_code is 0
        if return_code == 0:
            # check if specified ports are open on host
            connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            for port in port_list:
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
    logging.info("generating public-private key pair")
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
def initialize_system(server = False):
    # if config directory does not exists, create it
    config_dir = get_config_dir()
    if not os.path.isdir(config_dir):
        try:
            os.mkdir(config_dir)
        except:
            # show error and exit the application
            print("error: config dir cannot be created! exiting...")
            logging.critical("error: config dir cannot be created! exiting...")
            sys.exit(1)
    
    # set up logging
    logging.basicConfig(filename = os.path.join(config_dir, "log"),
        level = logging.DEBUG)
    
    # log initial messages
    logging.info("NetDog (alpha) is starting up")
    logging.info("System passed initial checks")

    # look if public key exists, generate if non existant
    if not os.path.exists(os.path.join(config_dir, "public_key"):
        key_pair = generate_keys()

        # write the newly generated keys to file
        logging.info("writing generated keys to file")
        with open(os.path.join(config_dir, "public_key"), "w") as pub_key_file:
            pub_key_file.write(key_pair["public_key"])
        
        with open(os.path.join(config_dir, "private_key"), "w") as pri_key_file:
            pri_key_file.write(key_pair["private_key"])

    # get the current network information
    logging.info("getting network information")
    network_info = retrieve_network_info()

    if network_info["interface"] == None:
        network_address = find_network(server)
    
    # if no known_server, initiate pairing
    if server == False:
        if os.path.exists(os.path.join(config_dir, "known_server")):
            # debug: future fix, check if known_server has a valid server
            pass
        else:
            # start client pairing request
            logging.info("the client is not paired with a server")
            request_to_pair(network_address)
