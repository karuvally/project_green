#!/usr/bin/env python3
# libgreener, alpha release
# Copyright 2018, Aswin Babu Karuvally

# import the serious stuff
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64


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



