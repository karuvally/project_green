#!/usr/bin/env python3
# NetDog Client module, alpha release
# Copyright 2018, Aswin Babu Karuvally

# import serious stuff
from libgreen import *


# the main function
def main():
    # start listening for connections
    listen_thread = threading.Thread(target = create_new_listen_socket,
        args = 1994)
    
    # initialize the system
    initialize_system()


# call the main function
main()
