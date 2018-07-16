#!/usr/bin/env python3
# Project Green, daemon, alpha release
# Copyright 2018, Aswin Babu Karuvally

# import the serious stuff
import socket
import subprocess
import os
import sys


# check and set up essential stuff
def initialize_system(config_dir):
    if not os.path.isdir(config_dir):
        try:
            os.mkdir(config_dir)
        except:
            print("error: config dir cannot be created! exiting...")
            sys.exit(1)


#writes data to the log file
def write_to_log (matter, config_dir):
    log_path = os.path.join(config_dir, "log")
    try:
        log_file = open (log_path, "a")

        log_file.write (time.strftime("[%d-%b-%Y %H:%M:%S] "))
        log_file.write (matter + "\n")
        log_file.close()
    except:
        print("error: cannot write to log! exiting...")
        sys.exit(1)


# create socket and listen
def create_socket():
    try:
        daemon_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        daemon_socket.bind(("0.0.0.0", 1337))
        daemon_socket.listen(5) # debug

        while True:
            connection, client_address = daemon_socket.accept()
    except KeyboardInterrupt:
        print("exiting gracefully...")
    except:
        print("error: cannot bind to port 1337!")


# the main function
def main():
    # essential variables
    config_dir = os.path.join("/home", os.getlogin, ".green")

    # start the system up
    initialize_system()

    # create the socket for listening
    create_socket()


# run the maain function
main()
