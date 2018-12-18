#!/usr/bin/env python3
# libgreener, alpha release
# Copyright 2018, Aswin Babu Karuvally

# import the serious stuff
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import pwd


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
        ping = Popen(["ping", "-b", "-c", "1", str(ip_address)], stdout = PIPE)
    else:
        logging.info("checking if node " + str(ip_address) + " is up")
        ping = Popen(["ping", "-c", "1", str(ip_address)], stdout = PIPE)

    # do the ping and return result
    ping_out = ping.communicate()[0]
    return(not bool(ping.returncode))



# the ping function for threads 
def ping_sweep(ip_address, result):
    ping = Popen(["ping", "-c", "1", str(ip_address)], stdout = PIPE)
    ping_out = ping.communicate()[0]

    # returncode is 0 if ping is succesful, converting to bool
    result.append({
        "ip_address": ip_address,
        "online": not bool(ping.returncode)
    })


# write configuration to disk in JSON
def write_configuration(config, filename):
    # essential variables
    config_dir = get_config_dir()
    config_file_path = os.path.join(config_dir, filename)
    global thread_lock

    # acquire thread lock
    thread_lock.acquire()
    
    # write configuration
    with open(config_file_path, "w") as config_file:
        config_file.write(json.dumps(config))

    # release lock
    thread_lock.release()


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
        logging.warning(filename + " does not exist")

    # return configuration
    return config


# generate public-private key pair
def generate_keys():
    # essential variables
    key_length = 2048

    # set the size for the generated key
    logging.info("generating public-private key pair")
    key = RSA.generate(key_length, e = 65537)
    
    # create public-private key pair
    public_key = key.publickey().exportKey("PEM")
    private_key = key.exportKey("PEM")

    # return key pair as dictionary
    return({
        "key_length_bits": key_length,
        "public_key": public_key.decode(),
        "private_key": private_key.decode()
    })


# do the actual decryption
def decrypt_stuff(blob, key, key_length_bits):
    # essential variables
    offset = 0
    decrypted_stuff = b""
    chunk_size = int(key_length_bits / 8)

    # do base64 decode
    blob = base64.b64decode(blob)

    # generate key object
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)

    # loop till entire blob is decrypted
    while offset < len(blob):
        # get the chunk
        chunk = blob[offset : offset + chunk_size]

        # decrypt chunk, add it to decrypted stuff
        decrypted_stuff += rsakey.decrypt(chunk)

        # increase offset by chunk size
        offset += chunk_size

    # return stuff
    return decrypted_stuff


# do the actual encryption
def encrypt_stuff(blob, key, key_length_bits):
    # essential variables
    offset = 0
    encrypted_blob = b""
    end_loop = False
    
    # convert blob to bytes
    blob = str(blob).encode()

    # generate key object
    rsa_key = RSA.importKey(key)
    rsa_key = PKCS1_OAEP.new(rsa_key)

    # calculate chunk size
    key_length_bytes = key_length_bits / 8
    chunk_size = int(key_length_bytes - 42)

    # loop over blob till encryption completes 
    while not end_loop:
        # get the chunk
        chunk = blob[offset : offset + chunk_size]

        # if chunk is too small, do padding
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += b" " * (chunk_size - len(chunk))

        # append chunk to overall blob 
        encrypted_blob += rsa_key.encrypt(chunk)

        # increase offset by chunk size
        offset += chunk_size

    # return encrypted blob in base64
    return base64.b64encode(encrypted_blob)



