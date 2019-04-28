#!/usr/bin/env python3
# simple program to test PyNaCl

# import the serious stuff
from libgreen import *
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
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
        "public_key": public_key.encode(encoder=nacl.encoding.HexEncoder),
        "private_key": private_key.encode(encoder=nacl.encoding.HexEncoder)
    })


# decrypt an incoming message
def decrypt_message(input_transmission):
    # load essential data
    keys = read_configuration("keys")
    known_nodes = read_configuration("known_nodes")

    # load localhost's keys
    receiver_priv_key = Privatekey(
        keys["private_key"],
        encoder = nacl.encoding.HexEncoder
    )

    # load sender's keys
    sender_id = input_transmission["sender_id"]
    send_pub_key = PublicKey(
        known_nodes[sender_id]["public_key"]
    )

    # decrypt the message
    message = decrypt_stuff(message, private_key, key_length)

    # recover the dictionary from message
    message = ast.literal_eval(message.decode())

    # return decrypted message
    return message


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
    encrypted_message = encrypt_box.encrypt(message.encode())

    # return the encrypted message
    return encrypted_message

