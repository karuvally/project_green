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
    listen_thread = threading.Thread(target = create_new_listen_socket,
        args = [1994])

    listen_thread.start()

    # make sure we have usable network
    setup_network()

# call the main function
main()
