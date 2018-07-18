#!/usr/bin/env python3
# Project Green, daemon, alpha release
# Copyright 2018, Aswin Babu Karuvally

# import the serious stuff
from libgreen import *


# the main function
def main():
    # essential variables
    config_dir = os.path.join("/home", os.getlogin(), ".green")

    # start the system up
    write_to_log("starting up the daemon", config_dir)
    initialize_system(config_dir)

    # create the socket for listening
    write_to_log("trying to create a socket", config_dir)
    create_server_socket(1337)

    # end of the journey
    write_to_log("exiting peacefully\n", config_dir)
    sys.exit(0)


# run the main function
main()
