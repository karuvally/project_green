#!/usr/bin/env python3
# NetDog Server module, alpha release
# Copyright 2018, Aswin Babu Karuvally

# import serious stuff
from libgreen import *


# the main function
def main():
    # initialize the system
    initialize_system(server = True)

    # listen for commands from UI
    
    # listen for message from clients
    create_new_listen_socket(1337)

    # send message to clients if necessary


# call the main function
main()