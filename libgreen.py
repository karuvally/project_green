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
import pathlib
import threading
import netaddr
from Crypto.PublicKey import RSA
from subprocess import Popen, PIPE


# store the newly paired server info
def store_server_info(server_id, public_key):
    # essential stuff
    config_dir = get_config_dir()
    logging.info("storing public key of server " + server_id)

    # write the new server info to file
    with open(os.path.join(config_dir, "known_server"), "w") as server_file:
        server_file.write(server_id + "\n")
        server_file.write(public_key)


# check if the running program is server
def is_server():
    if sys.argv[0].rfind("server") != -1:
        return True
    
    return False


# send data through network
def send_message(destination_ip, port, command, payload):
    # get the hostname of the machine
    hostname = socket.gethostname()

    # generate message
    message = hostname + "," + command + "," + payload

    # create socket, connect to destination IP
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.connect((destination_ip, port))

    # send the actual data
    connection.sendall(message.encode())


# load information about known_server
def load_known_server():
    # get configuration directory
    config_dir = get_config_dir()
    known_server_file_path = os.path.join(config_dir, "known_server")

    # exit if the known_server file does not exist
    if not os.path.exists(known_server_file_path):
        logging.warning("known_server file does not exist")
        return None

    # load data from known_server file
    with open(known_server_file_path, "r") as known_server_file:
        known_server_info = known_server_file.read().strip(",")

    return known_server_info


# load the list of nodes on the network
def load_nodes():
    # essential varilables
    config_dir = get_config_dir()
    return_data = []
    known_nodes_dir = os.path.join(config_dir, "known_nodes")

    # load known nodes info
    for node_id in os.listdir(known_nodes_dir):
        with open(os.path.join(known_nodes_dir, node_id)) as known_node_file:
            return_data.append([node_id, known_node_file.read()])

    # return stuff
    return return_data


# try to load public / private keys
def load_keys(key_type):
    # essential varilables
    config_dir = get_config_dir()
    key = None
    key_path = os.path.join(config_dir, key_type) 

    if os.path.exists(key_path):
        logging.info("loading " + key_type)
        with open(key_path, "r") as key_file:
            key = key_file.read()

    return key


# send request to server for pairing
def request_to_pair(network_info):
    # get configuration directory
    config_dir = get_config_dir()

    # find server
    server = find_hosts(network_info, mode = "server")
    
    # get the public key
    public_key = load_keys("public_key")

    # send pairing request
    logging.info("sending pairing request")
    send_message(server[0]["ip_address"], 1337, "pair", public_key)


# the ping function for threads 
def ping_sweep(ip_address, result):
    ping = Popen(["ping", "-c", "1", str(ip_address)], stdout = PIPE)
    ping_out = ping.communicate()[0]

    # returncode is 0 if ping is succesful, converting to bool
    result.append({
        "ip_address": ip_address,
        "online": not bool(ping.returncode)
    })


# ping ip address and return status
def ping_address(ip_address, broadcast = False):
    if broadcast == True:
        logging.info("checking if network " + str(ip_address) + " is up")
        ping = Popen(["ping", "-b", "-c", "1", str(ip_address)], stdout = PIPE)
    else:
        logging.info("checking if node " + str(ip_address) + " is up")
        ping = Popen(["ping", "-c", "1", str(ip_address)], stdout = PIPE)

    # do the ping and return result
    ping_out = ping.communicate()[0]
    return(not bool(ping.returncode))


# retrieve network info from known_network
def retrieve_network_info():
    # essential variables
    config_dir = get_config_dir()
    network_status = False 
    interface = None
    network_address = None
    netmask = None
    known_network_file_path = os.path.join(config_dir, "known_network")

    # look if known_network exists
    if os.path.exists(known_network_file_path):
        logging.info("using known network")
        with open(known_network_file_path, "r") as known_network_file:
            network_info = known_network_file.read().rstrip().split(",")
            interface = network_info[0]
            network_address = network_info[1]
            netmask = network_info[2]

        # look if network is up, network is up if network_status == 0
        network_status = ping_address(network_address, broadcast = True)

        if network_status == False:
            logging.info("known network is down")

    else:
        logging.info("no known network exists")
    
    return ({
        "interface": interface,
        "network_address": network_address,
        "netmask": netmask,
        "network_status": network_status
    })


# find a usable network interface
def probe_interfaces(server = False):
    # essential variables
    config_dir = get_config_dir()
    host_list = None
    known_network_file_path = os.path.join(config_dir, "known_network")
    user_choice = None

    # find interfaces and remove loopback from them
    available_interfaces = netifaces.interfaces()
    available_interfaces.remove("lo")

    if server == True:
        print("choose network interface")
        for interface in available_interfaces:
            address_dict = netifaces.ifaddresses(available_interfaces[i])

            # skip interface if it lacks IPV4 stuff
            if not netifaces.AF_INET in address_dict:
                continue

            network_address = address_dict[netifaces.AF_INET][0]["addr"]
            print(interface, ":", network_address)

        while user_choice not in available_interfaces:
            user_choice = input("interface>")
            address_dict = netifaces.ifaddresses(user_choice)


        """
        print("choose network interface")
        for i in range(0, len(available_interfaces)):
            address_dict = netifaces.ifaddresses(available_interfaces[i])

            # skip the interface if it lacks IPv4 stuff
            if not netifaces.AF_INET in address_dict:
                continue

            # debug: printing i values causes numbers to skip
            network_address = address_dict[netifaces.AF_INET][0]["addr"]
            print(i+1, ") " + available_interfaces[i] + ": " + network_address)

        user_choice = int(input(">")) - 1

        interface = available_interfaces[user_choice]
        address_dict = netifaces.ifaddresses(interface)
        """

        # find network address
        network_address = address_dict[netifaces.AF_INET][0]["addr"]
        network_address = network_address[: network_address.rfind(".")]
        network_address += ".0"

        netmask = address_dict[netifaces.AF_INET][0]["netmask"]

        # append the data to network_info
        network_info = {
            "network_address": network_address,
            "netmask": netmask,
            "interface": available_interfaces[user_choice]
        }

        logging.info("interface " + interface + " with address " +
        network_address + " choosen by user")

    else:
        # loop through interfaces
        for interface in available_interfaces:
            # find address of each interface
            address_dict = netifaces.ifaddresses(interface)
            network_address = address_dict[netifaces.AF_INET][0]["addr"]
            network_address = network_address[: network_address.rfind(".")]
            network_address += ".0"

            netmask = address_dict[netifaces.AF_INET][0]["netmask"]

            # append the data to network_info
            network_info = {
                "network_address": network_address,
                "netmask": netmask,
                "interface": interface
            }

            # if nodes can be found, set current network as default
            host_list = find_hosts(network_info, mode = "both")

            # debug: anyway to make this more elegant?
            if host_list:
                logging.info("network: " + network_address + " found")
                break

    # debug: future fix, move this block outside the function
    if host_list or server == True:
        with open(known_network_file_path, "w") as known_network_file:
            known_network_file.write(interface + "," + network_address
            + "," + netmask)
    
    # return network address to calling function
    return network_info 


# get the config directory
def get_config_dir():
    # get the username
    user = pwd.getpwuid(os.getuid())[0]

    # stich the complete path
    config_dir = os.path.join("/home", user, ".config", "netdog")

    return config_dir


# accept pairing request from client
def accept_pairing_request(node_id, public_key):
    logging.info("pairing request received")

    # essential varilables
    config_dir = get_config_dir()
    
    # store the public_key, hostname pair to text file
    logging.info("storing public key and of client " + node_id)
    known_nodes_dir = os.path.join(get_config_dir(), "known_nodes")

    with open(os.path.join(known_nodes_dir, node_id), "w") as known_node_file:
        known_node_file.write(public_key)

    # get public_key of the server
    with open(os.path.join(config_dir, "public_key"), "r") as public_key_file:
        public_key = public_key_file.read().rstrip()

    # return the public key
    return public_key


# handle newly created connection, debug: implement threading
def handle_connection(connection):
    # essential variables
    client_ip = connection.getpeername()[0]
    config_dir = get_config_dir()

    # receive data from client
    message = receive_message(connection)
    
    # if command + payload cannot be splitted, might be encrypted
    separated_message = message.split(",", 1)

    # if message cannot be splitted, its corrupted
    if len(separated_message) != 2:
        logging.critical("corrupt message received over network")
        return None # debug: replace this by "retransmit" command
    
    # get the source node ID and data 
    node_id = separated_message[0]
    data = separated_message[1]

    # look if ID exists in known_clients or known_server
    node_id_list = [node_info[0] for node_info in load_nodes()]

    # handle the pairing request
    if node_id not in node_id_list:
        data = data.split(",")
        command = data[0]
        payload = data[1]

        if command == "pair":
            public_key = accept_pairing_request(node_id, payload) 
            send_message(client_ip, 1994, "pair_ack", public_key)

    # handle pair acknowledgement # debug: improve checks
    if not is_server() and load_known_server() == None:
        if command == "pair_ack":
            store_server_info(node_id, payload)

    # implement rest of the commands
    
    # close the connection
    connection.close()


# create listening socket and... listen for connections :D
def create_new_listen_socket(port):
    # create the socket
    daemon_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    daemon_socket.bind(("0.0.0.0", port))
    daemon_socket.listen(5) 
    logging.info("listening on port " + str(port))

    # listen for incoming connections
    while True:
        # accept connection
        connection, source_address = daemon_socket.accept()

        # pass the connection to connection handler
        logging.info("new connection received from " + source_address[0])
        handle_thread = threading.Thread(target = handle_connection,
            args = [connection])

        handle_thread.start()

    # close the listen socket
    daemon_socket.close()


# find a host running NetDog
def find_hosts(network_info, mode):
    # essential variables
    node_list = []
    host_info = []
    threads = []

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

    # generate the cidr address
    cidr_address = netaddr.IPNetwork(network_info["network_address"],
        network_info["netmask"])

    network = ipaddress.ip_network(cidr_address)

    # try new thread for each host
    logging.info("performing ping sweep")
    for ip_address in network.hosts():
        ping_thread = threading.Thread(target = ping_sweep,
            args = (ip_address, host_info))

        threads.append(ping_thread)
        ping_thread.start()

    # wait until all threads are finished
    for process in threads:
        process.join()

    # generate list of online hosts
    online_hosts = [host for host in host_info if host["online"] == True]

    # find local host's IP
    localhost_info = netifaces.ifaddresses(network_info["interface"])
    localhost_addr = localhost_info[netifaces.AF_INET][0]["addr"]

    # skip if the client is localhost
    for host in online_hosts:
        if str(host["ip_address"]) == localhost_addr:
            continue

        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        for port in port_list:
            # port is open if return value is 0
            if connection.connect_ex((str(host["ip_address"]), port)) == 0:
                if port == 1337:
                    server = True
                else:
                    server = False

                # add host to the node list
                node_list.append({
                    "ip_address": str(host["ip_address"]),
                    "server": server
                })

                # exit the loop
                break

    # return the node list
    return node_list


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
def receive_message(connection):
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
def initialize_system():
    # essential variables
    config_dir = get_config_dir()
    known_nodes_dir = os.path.join(config_dir, "known_nodes")

    # create config and known_nodes dir
    if not os.path.isdir(known_nodes_dir):
        try:
            pathlib.Path(known_nodes_dir).mkdir(parents = True, exist_ok = True)
        except:
            # show error and exit the application
            print("error: config dir cannot be created! exiting...")
            sys.exit(1)
    
    # set up logging
    logging.basicConfig(filename = os.path.join(config_dir, "log"),
        level = logging.DEBUG)

    # print logs to stderr
    logging.getLogger().addHandler(logging.StreamHandler())
    
    # log initial messages
    logging.info("NetDog (alpha) is starting up")
    logging.info("System passed initial checks")

    # look if public key exists, generate if non existant
    if not os.path.exists(os.path.join(config_dir, "public_key")):
        key_pair = generate_keys()

        # write the newly generated keys to file
        logging.info("writing generated keys to file")
        with open(os.path.join(config_dir, "public_key"), "wb") as pub_key_file:
            pub_key_file.write(key_pair["public_key"])
        
        with open(os.path.join(config_dir, "private_key"), "wb") as pri_key_file:
            pri_key_file.write(key_pair["private_key"])


# make sure NetDog can connect to network
def setup_network(server = False):
    # essential variables
    config_dir = get_config_dir()

    # get the current network information
    logging.info("getting network information")
    network_info = retrieve_network_info()

    if network_info["network_status"] == False:
        network_info = probe_interfaces(server)

    # if no known_server, initiate pairing
    if server == False:
        if os.path.exists(os.path.join(config_dir, "known_server")):
            # debug: future fix, check if known_server has a valid data
            pass
        else:
            # start client pairing request
            logging.info("the client is not paired with a server")
            request_to_pair(network_info)

