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
import signal
import json
from Crypto.PublicKey import RSA
from subprocess import Popen, PIPE

# global variables
thread_lock = threading.Lock()


# pair with client if necessary
def pair_if_necessary(message, node_ip):
    # exit if message does not have pair command
    if message["data"]["command"] != "pair":
        return

    # essential variables
    sender_id = message["hostname"]
    known_nodes_info = read_configuration("known_nodes")

    # generate node list
    if known_nodes_info:
        node_list = [node_id for node_id in known_nodes_info]

    if known_nodes_info and sender_id in node_list:
        return

    # accept pair request and get public_key of server
    public_key = accept_pairing_request(sender_id, node_ip, payload)

    # send pair acknowledgement
    send_message(1994, "pair_ack", public_key, destination_ip = node_ip)


# encrypt data to be send inside message
def encrypt_message(message, receiver_id):
    # essential variables
    encrypted_message = {}

    # load private key of localhost
    key_pair = read_configuration("keys")
    private_key = RSA.importKey(key_pair["private_key"])

    # load public key of receiver
    known_nodes = read_configuration("known_nodes")
    public_key = RSA.importKey(known_nodes[receiver_id]["public_key"])

    # encrypt data with private key of sender
    
    # encrypt message with public key of receiver

    # return the encrypted message


# stuff to do when client starts
def client_checklist(known_network_info):
    # essential variables
    config_dir = get_config_dir()

    # if no known_server is present, find one and pair
    if not os.path.exists(os.path.join(config_dir, "known_server")):
        # start client pairing request
        logging.info("the client is not paired with a server")
        request_to_pair(known_network_info)


# update a configuration file
def update_configuration(config, filename, force = False):
    # read configuration from file
    config_from_file = read_configuration(filename)

    # abort if no config file and force is False
    if not config_from_file and not force:
        return

    # continue if force is True
    elif not config_from_file and force:
        config_from_file = {}

    # update configuration
    config_from_file.update(config)

    # write configuration to file
    write_configuration(config_from_file, filename)


# cli for choosing network interface
def interface_chooser(interface_dump):
    # essential variables
    user_choice = None

    print("choose network interface")

    while user_choice not in interface_dump:
        for interface in interface_dump:
            print(interface, ":", interface_dump[interface]["network_address"])

        user_choice = input(">")

    return user_choice


# find usable network for client
def find_network(interface_dump):
    for interface in interface_dump:
        node_list = find_hosts(interface_dump[interface], "server")

        # return the interface if it has nodes
        if node_list != None:
            return interface
        else:
            continue

    # return None if no network is found
    return None


# read JSON configuration from disk
def read_configuration(filename):
    # essential variables
    config_dir = get_config_dir()
    config = None
    config_file_path = os.path.join(config_dir, filename)

    # read configuration
    if os.path.exists(config_file_path):
        logging.info("reading from " + filename)
        with open(config_file_path, "r") as config_file:
            config = json.loads(config_file.read())
    else:
        logging.warning(filename + " does not exist")

    # return configuration
    return config


# write configuration to disk in JSON
def write_configuration(config, filename):
    # essential variables
    config_dir = get_config_dir()
    config_file_path = os.path.join(config_dir, filename)
    global thread_lock

    # acquire thread lock
    thread_lock.acquire()
    
    # write configuration
    logging.info("writing into " + filename)
    with open(config_file_path, "w") as config_file:
        config_file.write(json.dumps(config))

    # release lock
    thread_lock.release()


# probe interfaces, the new way
def probe_interfaces():
    # essential variables
    interface_dict = {}

    # list available interfaces and remove loopback
    available_interfaces = netifaces.interfaces()
    available_interfaces.remove("lo")

    for interface in available_interfaces:
        # get all the information about the interface
        interface_details = netifaces.ifaddresses(interface)

        # remove interface if it lacks IPv4 stuff
        if not netifaces.AF_INET in interface_details:
            continue

        # extract required information from interface_details
        localhost_address = interface_details[netifaces.AF_INET][0]["addr"]
        netmask = interface_details[netifaces.AF_INET][0]["netmask"] 
        
        # generate network address
        network_address = localhost_address 
        network_address = network_address[: network_address.rfind(".")]
        network_address += ".0"

        # generate interface information dictionary
        interface_dict.update({interface: {
            "localhost_address": localhost_address,
            "network_address": network_address,
            "netmask": netmask,
            "interface": interface
        }})

    # return stuff
    return interface_dict


# update ip addresses in lookup table
def update_lookup_table(node_id, ip_address):
    # check if node is known
    known_nodes = read_configuration("known_nodes")
    if node_id not in known_nodes:
        logging.warning(node_id + " is unknown, address cannot be updated")
        return None

    # generate data to be updated
    update_config = {
        node_id: {
            "last_known_address": ip_address
        }
    }

    # update the data
    update_configuration(update_config, "known_nodes")
 

# exit gracefully when SIGINT happens
def signal_handler(signal, frame):
    logging.info("exiting gracefully\n")
    sys.exit(0)


# store the newly paired server info
def store_server_info(server_id, server_ip, public_key):
    # essential stuff
    config_dir = get_config_dir()
    logging.info("storing public key of server " + server_id)

    # prepare data to be written
    server_info = {
        "server_id": server_id,
        "server_ip": server_ip,
        "public_key": public_key
    }

    # write the new server info to file
    write_configuration(server_info, "known_server")


# check if the running program is server
def is_server():
    if sys.argv[0].rfind("server") != -1:
        return True
    
    return False


# send data through network
def send_message(port, command, payload, destination_id = None,
        destination_ip = None):
    # essential variables
    encrypt_flag = False

    # get the hostname of the machine
    hostname = socket.gethostname()

    # generate message
    data = {
        "command": command,
        "payload": payload
    }

    message = {
        "hostname": hostname,
        "data": data
    }

    # create socket, connect to destination IP
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.connect((destination_ip, port))

    # if command not pair, encrypt message
    if command != "pair":
        encrypt_flag = True
        message = encrypt_message(message, destination_id)

    # generate final output
    output = {
        "encrypted": encrypt_flag,
        "message": message
    }
    output = str(output)

    # send the message
    connection.sendall(output.encode())


# send request to server for pairing
def request_to_pair(network_info):
    # get configuration directory
    config_dir = get_config_dir()

    # find server
    server = find_hosts(network_info, mode = "server")
    
    # get the public key
    key_pair = read_configuration("keys")
    public_key = key_pair["public_key"]

    # send pairing request
    logging.info("sending pairing request")
    send_message(1337, "pair", public_key,
        destination_ip = server[0]["ip_address"])


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


# get the config directory
def get_config_dir():
    # get the username
    user = pwd.getpwuid(os.getuid())[0]

    # stich the complete path
    config_dir = os.path.join("/home", user, ".config", "netdog")

    return config_dir


# accept pairing request from client
def accept_pairing_request(node_id, node_ip, public_key):
    logging.info("pairing request received")

    # essential varilables
    config_dir = get_config_dir()
    
    # generate node_info dictionary for storing 
    logging.info("storing public key of client " + node_id)
    node_info = {
        node_id: {
            "public_key": public_key,
            "last_known_address": node_ip
        }
    }

    # store the dictionary to known_nodes file
    update_configuration(node_info, "known_nodes", force = True)

    # get public_key of the server
    key_pair = read_configuration("keys")
    server_key = key_pair["public_key"]

    # return the public key
    return server_key 


# handle newly created connection
def handle_connection(connection):
    # essential variables
    node_ip = connection.getpeername()[0]
    config_dir = get_config_dir()

    # receive data from client
    input_transmission = receive_message(connection)

    # if message is not encrypted, call pair
    if not input_transmission["encrypted"]:
        command = input_transmission["message"]["data"]["command"]

        if command == "pair":
            pair_if_necessary(input_transmission["message"], node_ip)
        
        elif command == "pair_ack":
            store_server_info(node_id, node_ip, payload)

        elif command == "ping":
            pass
    
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
    localhost_address = network_info["localhost_address"]

    # skip if the client is localhost
    for host in online_hosts:
        if str(host["ip_address"]) == localhost_address:
            continue

        # try connecting to the host
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
        "public_key": public_key.decode(),
        "private_key": private_key.decode()
    })


# handle the incoming data
def receive_message(connection):
    # an empty string for storing data
    transmission = ""

    while True:
        # receive transmission with buffer size as 16 bytes
        transmission_buffer = connection.recv(16)

        # continue if transmission_buffer is not None
        if transmission_buffer:
            # convert received transmission to unicode
            transmission += transmission_buffer.decode()
        else:
            break

    if not transmission:
        return None

    return dict(transmission)


# check and set up essential stuff
def initialize_system():
    # essential variables
    config_dir = get_config_dir()
    
    # make system capture Ctrl + C
    signal.signal(signal.SIGINT, signal_handler)

    # create config dir
    if not os.path.isdir(config_dir):
        try:
            pathlib.Path(config_dir).mkdir(parents = True, exist_ok = True)
        except:
            # show error and exit the application
            print("error: config dir cannot be created! exiting")
            sys.exit(1)
    
    # set up logging
    logging.basicConfig(
        filename = os.path.join(config_dir, "log"),
        level = logging.DEBUG)

    # print logs to stderr
    logging.getLogger().addHandler(logging.StreamHandler())
    
    # log initial messages
    logging.info("NetDog (alpha) is starting up")
    logging.info("System passed initial checks")

    # look if public key exists, generate if non existant
    if not read_configuration("keys"):
        key_pair = generate_keys()
        write_configuration(key_pair, "keys")


# make sure NetDog can connect to network
def setup_network(server = False):
    # essential variables
    config_dir = get_config_dir()
    interface_dump = probe_interfaces()
    known_network_info = read_configuration("known_network")

    # get last known network information
    logging.info("getting network information")

    # if no known network, find a usable one
    if not known_network_info:
        if server:
            # launch network chooser
            usable_interface = interface_chooser(interface_dump)

        # if client, automatically find usable interface
        elif not server:
            while True:
                usable_interface = find_network(interface_dump)
                if usable_interface:
                    break
                time.sleep(30)

        # save the newly found network 
        known_network_info = interface_dump[usable_interface]
        write_configuration(known_network_info, "known_network")

    # if there is a known network, do as follows, debug
    else:
        pass

    # if localhost is client, do stuff :D
    if server == False:
        client_checklist(known_network_info)
