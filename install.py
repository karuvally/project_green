#!/usr/bin/env python3
# Project Green, installation script

# import all the serious stuff
from libgreen import generate_keys

# the main function
def main():
    # look if running as root
    # look if a server exists on network
    # install client if server == True
    # install server if server == False
    # if client, create daemon service

    # create public/private key pair
    keys = generate_keys()

    # write private key to $CONFIG_DIR if server
    # write private key to /etc/pgreen/private.key with mode 600

    # if server, start listening for client pairing
    # if client, connect to server, pair
    # start the daemon


# run the main function
main()
