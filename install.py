#!/usr/bin/env python3
# Project Green, Install script
# Copyright 2018, Aswin Babu Karuvally

# import all the serious stuff
from libgreen import find_server
import os
import sys


# the main function
def main():
    # look if running as root
    if os.getuid() != 0:
        print("please run the script as root")
        sys.exit(0)

    # look if a server exists on network
    find_server("192.168.122.0")

    # install client if server == True
    # install server if server == False
    # if client, create daemon service

    # create public/private key pair
    # keys = generate_keys()

    # write private key to $CONFIG_DIR if server
    # write private key to /etc/pgreen/private.key with mode 600

    # if server, start listening for client pairing
    # if client, connect to server, pair
    # start the daemon


# run the main function
main()
