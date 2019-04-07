#!/usr/bin/env python3
# post installation script for Netdog

# import serious stuff
import os
import subprocess


# execute command
def execute_command(command):
    return_code = subprocess.call(command, shell=True)

    if return_code != 0:
        logging.warning(command + " cannot be executed, exiting")
        sys.exit(1)


# the main function
def main():
    # create netdog user
    execute_command("adduser --disabled-password --gecos Netdog netdog")

    # set password for netdog
    pass


if __name__ == "__main__":
    main()
