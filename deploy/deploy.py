#!/usr/bin/env python3
# Netdog deploy script, alpha release
# Copyright 2019, Aswin Babu Karuvally

# import serious stuff
import argparse


# the main function
def main():
    # setup the argument parser
    parser = argparse.ArgumentParser(
        description = "Netdog deployer utility, alpha release"
    )
    parser.add_argument(
        "-s", 
        "--server", 
        help = "install the server", 
        action = "store_true",
        dest = "server"
    )
    arguments = parser.parse_args()
    
    # if not root, quit
    
    

if __name__ == "__main__":
    main()
