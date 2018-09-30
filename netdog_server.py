#!/usr/bin/env python3
# NetDog Server module, alpha release
# Copyright 2018, Aswin Babu Karuvally

# import serious stuff
from libgreen import *


# the main function
def main():
    # initialize the system
    initialize_system()

    # make sure NetDog can connect to network
    setup_network(server = True)

    # listen for message from clients
    create_new_listen_socket(1337)


# call the main function
#main()
