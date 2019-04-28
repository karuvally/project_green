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


print(generate_keys())
