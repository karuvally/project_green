#!/usr/bin/env python3
# simple program to test PyNaCl

# import the serious stuff
from libgreen import *
import nacl.utils
from nacl.public import PrivateKey, Box
import pdb


# generate public-private key pair
def generate_keys():
    logging.info("generating public-private key pair")

    # create public/private pair
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    key_length = private_key.SIZE * 8

    # return key pair as dictionary
    return({
        "key_length_bits": key_length,
        "public_key": public_key.encode(),
        "private_key": private_key.encode()
    })


# encrypt data to be send inside message
def encrypt_message(message, receiver_id):
    # load public key of receiver
    known_nodes = read_configuration("known_nodes")
    receiver_pub_key = known_nodes[receiver_id]["public_key"]
    sender_priv_key = read_configuration("keys")["private_key"]

    # encrypt message with public key of receiver
    encrypt_box = Box(sender_priv_key, receiver_pub_key)
    encrypted_message = encrypt_box.encrypt(message.encode())

    # return the encrypted message
    return encrypted_message

