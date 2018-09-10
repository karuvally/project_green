#!/usr/bin/env python3
# NetDog Client module, alpha release
# Copyright 2018, Aswin Babu Karuvally

# import serious stuff
from libgreen import *


# the main function
def main():
    # initialize the system
    initialize_system()

    # start listening for connections
    create_new_listen_socket(1994)


# call the main function
main()
