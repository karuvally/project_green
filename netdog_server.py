#!/usr/bin/env python3
# NetDog Server module, alpha release
# Copyright 2018, Aswin Babu Karuvally

# import serious stuff
from libgreen import *
from web_server import start_web_server


# the main function
def main():
    # initialize the system
    initialize_system()

    # make sure NetDog can connect to network
    setup_network(server = True)

    # listen for message from clients
    listen_thread = threading.Thread(target = create_new_listen_socket,
        args = [1337])

    listen_thread.start()

    # start web server
    start_web_server()


# call the main function
main()
