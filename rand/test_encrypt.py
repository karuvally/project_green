#!/usr/bin/env python3

# import the serious stuff
from libgreen import *


def test():
    text_string = "Hello World"
    key_info = read_configuration("keys")
    key_length = key_info["key_length_bits"]
    public_key = key_info["public_key"]
    private_key = key_info["private_key"]

    # the message
    message = {
        'hostname': 'ThinkPad-L440',
        'data': {
            'command': 'pair',
            'payload': '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+oct9Yup4A4juyGydsyDdxkwd\n6OzEscrP4sbGt2qCC2hUYLlFKlXiRHG7gh1NWydrN3a9GHAJCml9KJcuEHSdvN2z\nYeW0VtWgmlWAItMGwHxx4fFCKzqQfN/F3n968YjHfqV3I9d+fbFQflykCAsmtCie\nDJPMUtrjzV8Wpe6X5QIDAQAB\n-----END PUBLIC KEY-----'
        }
    }

    """
    # generate the encrypted message
    encrypted_blob = encrypt_message(message, "netdog-client")
    with open("output", "wb") as output_file:
        output_file.write(encrypted_blob)
    """

    # decrypt the message
    with open("output", "rb") as input_file:
        encrypted_blob = input_file.read()

    decrypted_message = decrypt_message(encrypted_blob)
    return decrypted_message
    
    """
    encrypted_blob = encrypt_stuff(text_string, public_key, key_length)
    decrypted_blob = decrypt_stuff(encrypted_blob, private_key, key_length)
    print(decrypted_blob)
    """

test()
