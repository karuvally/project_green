#!/usr/bin/env python3
# libgreen, alpha release
# Copyright 2018, Aswin Babu Karuvally

# import the serious stuff
import os
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
import ast
import base64
import pwd
import pdb
import nacl.utils
from subprocess import Popen, PIPE
from datetime import datetime
from nacl.public import PrivateKey, PublicKey, Box

# global variables
beacon_db = {}

# thread locks
configuration_lock = threading.Lock()
beacon_lock = threading.Lock()


# generate list of active clients
def get_active_clients():
    # essential variables
    active_clients = {}

    # read beacon db
    beacon_db = read_beacon_db()

    # return None if empty beacon_db
    if not beacon_db:
        return None

    # fetch active clients and their info
    for client in beacon_db:
        active_clients.update({
            client: read_configuration(
                "known_nodes")[client]["last_known_address"]
        })

    return active_clients


# read beacon_db from in memory file
def read_beacon_db():
    # if beacon_db lock exists, wait
    while True:
        if os.path.exists("/dev/shm/netdog/beacon_db.lock"):
            time.sleep(.2)
        else:
            break
    
    # if beacon_db does not exist, return None
    if not os.path.exists("/dev/shm/netdog/beacon_db"):
        return None

    # read beacon_db into a dictionary
    beacon_db_file = open("/dev/shm/netdog/beacon_db")
    beacon_db = ast.literal_eval(beacon_db_file.read())
    beacon_db_file.close()

    # return the dictionary
    return beacon_db


# write beacon_db to in memory file 
def write_beacon_db():
    # use global beacon_db variable
    global beacon_db

    # place lock file
    lock_file = open("/dev/shm/netdog/beacon_db.lock", "w")
    lock_file.write("")
    lock_file.close()

    # open beacon_db file
    beacon_db_file = open("/dev/shm/netdog/beacon_db", "w")

    # write beacon_db to in memory file
    beacon_db_file.write(str(beacon_db))

    # close the file
    beacon_db_file.close()

    # delete the lock file
    os.remove("/dev/shm/netdog/beacon_db.lock")


# send a beacon every 30s
def beacon_system():
    # start the loop
    while True:
        send_beacon()
        time.sleep(30)


# remove older beacons from beacon_db
def cleanup_beacon_db():
    # get the global variables
    global beacon_db
    global beacon_lock

    # essential variables
    expired_clients = []
    
    while True:
        # cleanup to be done every 30s 
        time.sleep(30)
        
        # skip if empty beacon_db
        if not beacon_db:
            continue
        
        # acquire lock
        beacon_lock.acquire()
        
        # get current time
        current_time = int(datetime.now().timestamp())
        
        # generate expired clients list
        for client in beacon_db:
            if current_time - beacon_db[client]["beacon_time"] > 30:
                expired_clients.append(client)
                logging.info("beacon from client " + client + " expired")

        # remove expired clients from beacon_db
        for client in expired_clients:
            beacon_db.pop(client)
        
        # release lock
        beacon_lock.release()

        # write beacon_db to in memory file
        write_beacon_db()


# update the beacon database
def update_beacon_db(client_id, payload):
    # use global becon_db
    global beacon_db
    global beacon_lock
    
    # acquire lock
    beacon_lock.acquire()
    
    # get current time, insert it to payload
    current_time = int(datetime.now().timestamp())
    payload.update({"beacon_time": current_time})
    
    # insert client_id, payload to beacon_db
    beacon_db.update({client_id: payload})
    
    # release lock
    beacon_lock.release()

    # write to beacon_db to in memory file
    write_beacon_db()
    
    # log the incident
    logging.info("beacon received from " + client_id)


# send status beacon
def send_beacon():
    # get config directory
    config_dir = get_config_dir()
    
    # checks
    if os.path.exists(os.path.join(config_dir, "known_network")):
        known_network = read_configuration("known_network")
        if "server_id" in known_network:
    
            # get id of server
            server_id = read_configuration("known_network")["server_id"]

            # collect various system stats
            system_stats = Popen(
                ["conky", "-c", "/opt/netdog/src/conky.conf"],
                stdout=PIPE
            )
            
            # prepare the payload
            system_stats = system_stats.stdout.read().decode()
            system_stats = ast.literal_eval(system_stats)

            # send the beacon
            send_message(1337, "beacon", system_stats, destination_id=server_id) 


# update specific values in dict without destroying others
def dict_update(original_config, new_config):
    for key, value in new_config.items():
        if isinstance(value, dict):
            original_config[key] = dict_update(original_config.get(key, {}), value)
        else:
            original_config[key] = value
    return original_config


# get the config directory
def get_config_dir():
    # get the username
    user = pwd.getpwuid(os.getuid())[0]

    # stich the complete path
    config_dir = os.path.join("/home", user, ".config", "netdog")

    return config_dir


# ping ip address and return status
def ping_address(ip_address, broadcast = False):
    if broadcast == True:
        logging.info("checking if network " + str(ip_address) + " is up")
        ping = Popen(
            ["ping", "-b", "-c", "1", "-w", "1", str(ip_address)], stdout = PIPE
        )
    else:
        logging.info("checking if node " + str(ip_address) + " is up")
        ping = Popen(
            ["ping", "-c", "1", "-w", "1", str(ip_address)], stdout = PIPE
        )

    # do the ping and return result
    ping_out = ping.communicate()[0]
    return(not bool(ping.returncode))


# the ping function for threads 
def ping_sweep(ip_address, result):
    ping = Popen(["ping", "-c", "1", "-w", "1", str(ip_address)], stdout = PIPE)
    ping_out = ping.communicate()[0]

    # returncode is 0 if ping is succesful, converting to bool
    result.append({
        "ip_address": ip_address,
        "online": not bool(ping.returncode)
    })


# write configuration to disk in JSON
def write_configuration(config, filename, log=True):
    # essential variables
    config_dir = get_config_dir()
    config_file_path = os.path.join(config_dir, filename)
    global configuration_lock

    # acquire thread lock
    configuration_lock.acquire()
    
    # write configuration
    with open(config_file_path, "w") as config_file:
        config_file.write(json.dumps(config))

    # release lock
    configuration_lock.release()
    
    # log the event
    if log:
        logging.info("creating " + filename + " with configuraiton")


# read JSON configuration from disk
def read_configuration(filename):
    # essential variables
    config_dir = get_config_dir()
    config = None
    config_file_path = os.path.join(config_dir, filename)

    # read configuration
    if os.path.exists(config_file_path):
        with open(config_file_path, "r") as config_file:
            config = json.loads(config_file.read())
    else:
        logging.warning("trying to read " + filename + ", but it does not exist")

    # return configuration
    return config


# generate public-private key pair
def generate_keys():
    logging.info("generating public-private key pair")

    # create public/private pair
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    key_length = private_key.SIZE * 8

    # get key strings
    public_key = public_key.encode(encoder=nacl.encoding.HexEncoder).decode()
    private_key = private_key.encode(encoder=nacl.encoding.HexEncoder).decode() 

    # return key pair as dictionary
    return({
        "key_length_bits": key_length,
        "public_key": public_key,
        "private_key": private_key 
    })


# submit command for execution over nodes
def submit_command(command):
    # get known nodes
    known_nodes = read_configuration("known_nodes")

    # run the command on each node
    for node in known_nodes:
        send_message(1994, "execute", command, destination_id=node)


# receive the file from broadcast
def receive_broadcast(message, sender_ip):
    # get the file contents
    filename = message["data"]["payload"]["filename"]
    file_data = message["data"]["payload"]["file_data"]

    # write the file
    with open(os.path.join("/share", filename), "wb") as output_file:
        output_file.write(file_data)


# send a file to all nodes 
def send_file(file_path, target_node):
    # read the file
    with open(file_path, "rb") as broadcast_file:
        file_data = broadcast_file.read()

    # generate the payload
    payload = {
        "filename": os.path.split(file_path)[-1],
        "file_data": file_data
    }

    # send the file to node 
    send_message(1994, "broadcast_file", payload, destination_id=target_node)


# check if the host is a netdog client/server
def check_if_node(host, port_list, node_list):
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


# execute command, send back the result
def execute_command(message, sender_ip):
    # extract the command
    command = message["data"]["payload"]

    # create command object, execute
    command_object = Popen(command, stdout=PIPE, shell=True)

    # get the output
    command_out = command_object.communicate()


# decrypt an incoming message
def decrypt_message(input_transmission):
    # load essential data
    keys = read_configuration("keys")
    known_nodes = read_configuration("known_nodes")
    message = input_transmission["message"]

    # load localhost's keys
    receiver_priv_key = PrivateKey(
        keys["private_key"],
        encoder = nacl.encoding.HexEncoder
    )

    # load sender's keys
    sender_id = input_transmission["sender_id"]
    sender_pub_key = PublicKey(
        known_nodes[sender_id]["public_key"],
        encoder = nacl.encoding.HexEncoder
    )

    # decrypt the message
    decrypt_box = Box(receiver_priv_key, sender_pub_key)
    decrypted_message = decrypt_box.decrypt(message)

    # recover the dictionary from message
    decrypted_message = ast.literal_eval(decrypted_message.decode())

    # return decrypted message
    return decrypted_message


# pair with client if necessary
def pair_if_necessary(message, node_ip):
    # essential variables
    sender_id = message["hostname"]
    payload = message["data"]["payload"]
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
    # read the know_nodes file
    known_nodes = read_configuration("known_nodes")

    # decode keys
    receiver_pub_key = PublicKey(
        known_nodes[receiver_id]["public_key"],
        encoder = nacl.encoding.HexEncoder
    )

    sender_priv_key = PrivateKey(
        read_configuration("keys")["private_key"],
        encoder = nacl.encoding.HexEncoder
    )

    # encrypt message with public key of receiver
    encrypt_box = Box(sender_priv_key, receiver_pub_key)
    encrypted_message = encrypt_box.encrypt(str(message).encode())

    # return the encrypted message
    return encrypted_message


# stuff to do when client starts
def client_checklist(known_network_info):
    # essential variables
    config_dir = get_config_dir()

    # if no known server, find one and pair
    if not os.path.exists(os.path.join(config_dir, "known_nodes")):
        # start client pairing request
        logging.info("the client is not paired with a server")
        request_to_pair(known_network_info)

    # get last known and current IP address
    last_known_address = known_network_info["localhost_address"]
    current_network = probe_interfaces()[known_network_info["interface"]]
    current_address = current_network["localhost_address"]

    # alert server if there is change in IP
    if current_address != last_known_address:
        server_id = read_configuration("known_network")["server_id"]
        
        node_info = {
            "node_id": socket.gethostname(),
            "current_address": current_address
        }

        send_message(1337, "update_ip", node_info, destination_id=server_id)

        # update local last_known_address, debug: implement proper ACK
        update_configuration({"localhost_address": current_address}, "known_network")
            

# update a configuration file
def update_configuration(config, filename, force=False):
    # read configuration from file
    config_from_file = read_configuration(filename)

    # abort if no config file and force is False
    if not config_from_file and not force:
        return

    # continue if force is True
    elif not config_from_file and force:
        new_configuration = config
    
    elif config_from_file:
        new_configuration = dict_update(config_from_file, config)

    # write configuration to file
    write_configuration(new_configuration, filename, log=False)
    
    if config_from_file:
        logging.info("updating " + filename + " with new configuration")
    else:
        logging.info("creating " + filename + " with configuration")


# find usable network for client
def find_network():
    # essential variables
    interface_dump = probe_interfaces()

    for interface in interface_dump:
        node_list = find_hosts(interface_dump[interface], "server")

        # return the interface if it has nodes
        if node_list != None:
            return interface
        else:
            continue

    # return None if no network is found
    return None


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


# update ip addresses in known nodes 
def update_known_nodes(node_info):
    # check if node is known
    known_nodes = read_configuration("known_nodes")
    if node_info["node_id"] not in known_nodes:
        logging.warning(node_id + " is unknown, address cannot be updated")
        return None

    # generate data to be updated
    update_config = {
        node_info["node_id"]: {
            "last_known_address": node_info["current_address"]
        }
    }

    # update the data
    update_configuration(update_config, "known_nodes")
 

# exit gracefully when SIGINT happens
def signal_handler(signal, frame):
    logging.info("exiting gracefully\n")
    sys.exit(0)


# store the newly paired server info
def store_server_info(message, server_ip):
    # essential stuff
    config_dir = get_config_dir()
    server_id = message["hostname"]
    public_key = message["data"]["payload"]

    # write to log :)
    logging.info("storing public key of server " + server_id)

    # prepare data to be written
    server_info = {
        server_id: {
            "last_known_address": server_ip,
            "public_key": public_key,
            "type": "server"
        }
    }

    # write the new server info to file, debug: write/update?
    write_configuration(server_info, "known_nodes")

    # write server_id to known_network
    update_configuration({"server_id": server_id}, "known_network")


# check if the running program is server
def is_server():
    if sys.argv[0].rfind("server") != -1:
        return True

    return False


# send data through network
def send_message(port, command, payload, destination_id=None,
        destination_ip=None):
    # essential variables
    encrypt_flag = False

    # following commands won't get encrypted
    do_not_encrypt_list = [
        "pair",
        "pair_ack"
    ]

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

    # retrieve destination_ip from id
    if destination_id:
        known_nodes = read_configuration("known_nodes")
        destination_ip = known_nodes[destination_id]["last_known_address"]

    # create socket, connect to destination IP
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.connect((destination_ip, port))
    except:
        logging.warning("connection to " + str(destination_ip) + " failed")
        return

    # if command not pair, encrypt message
    if command not in do_not_encrypt_list:
        encrypt_flag = True
        message = encrypt_message(message, destination_id)

    # generate final output
    output = {
        "encrypted": encrypt_flag,
        "sender_id": hostname,
        "message": message
    }

    # convert output to bytes
    output = str(output).encode()

    # send the message
    connection.sendall(output)


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
            "last_known_address": node_ip,
            "type": "client"
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
    sender_ip = connection.getpeername()[0]
    config_dir = get_config_dir()

    # receive data from client
    input_transmission = receive_transmission(connection)

    if not input_transmission:
        logging.info("ping received from " + sender_ip)
        connection.close()
        return

    # report the received connection
    logging.info("connection received from " + sender_ip)

    # extract essential info from transmission
    message = input_transmission["message"]
    command = message["data"]["command"]

    # act according to received command, debug: replace with case?
    if command == "pair":
        pair_if_necessary(message, sender_ip)
    
    elif command == "pair_ack":
        store_server_info(message, sender_ip)

    elif command == "execute":
        execute_command(message, sender_ip)

    elif command == "broadcast_file":
        receive_broadcast(message, sender_ip)

    elif command == "update_ip":
        update_known_nodes(message["data"]["payload"])
        
    elif command == "beacon":
        update_beacon_db(message["hostname"], message["data"]["payload"])

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
    ping_threads = []
    checker_threads = []

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

        ping_threads.append(ping_thread)
        ping_thread.start()

    # wait until all threads are finished
    for thread in ping_threads:
        thread.join()

    # generate list of online hosts
    online_hosts = [host for host in host_info if host["online"] == True]

    # find local host's IP
    localhost_address = network_info["localhost_address"]

    # remove localhost from online_hosts
    online_hosts = [host for host in online_hosts
        if str(host["ip_address"]) != localhost_address]

    # check if the host is a netdog client/server
    for host in online_hosts:
        checker_thread = threading.Thread(target = check_if_node,
            args = [host, port_list, node_list])

        checker_threads.append(checker_thread)
        checker_thread.start()

    # wait for threads to finish
    for thread in checker_threads:
        thread.join()

    # return the node list
    return node_list


# handle the incoming data
def receive_transmission(connection):
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

    # pings produce empty transmissions
    if not transmission:
        return None

    # convert the transmission to dictionary
    transmission = ast.literal_eval(transmission)

    # decrypt if transmission is encrypted
    if transmission["encrypted"]:
        message = decrypt_message(transmission)
        transmission.update({"message": message})

    # return message
    return transmission


# check and set up essential stuff
def initialize_system(server=False):
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

    # setup tmpfs dir
    if server and not os.path.isdir("/dev/shm/netdog"):
        os.mkdir("/dev/shm/netdog")
    
    # set up logging
    format_string = "[%(asctime)s] %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    logging.basicConfig(
        filename = os.path.join(config_dir, "log"),
        level = logging.DEBUG,
        format = format_string,
        datefmt = date_format)

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
def setup_network(server=False):
    # essential variables
    config_dir = get_config_dir()
    interface_dump = probe_interfaces()
    known_network_info = read_configuration("known_network")

    # get last known network information
    logging.info("getting network information")

    # if no known network and is server, pause, debug
    while not known_network_info and server:
        time.sleep(10)
        known_network_info = read_configuration("known_network")

    # if no known network and is client, find network automatically
    if not known_network_info and not server:
        while True:
            usable_interface = find_network()
            if usable_interface:
                break
            time.sleep(30)

        # write the found network to config
        known_network_info = interface_dump[usable_interface]
        write_configuration(known_network_info, "known_network")
        
    # start beacon_db cleanup thread
    if server:
        cleanup_beacon_db_thread = threading.Thread(target=cleanup_beacon_db)
        cleanup_beacon_db_thread.start()

    # else do client specific network stuff
    else:
        client_checklist(known_network_info)

