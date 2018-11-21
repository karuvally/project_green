#!/usr/bin/env python3

# import serious stuff
from libgreen import *

def main():
    message = {
        'hostname': 'ThinkPad-L440',
        'data': {
            'command': 'pair',
            'payload': 'This is a test message'         
        }
    }

    blob = encrypt_message(message, "ThinkPad-L440")
    result = decrypt_message(blob)

    print(result, type(result))

# run main
main()
