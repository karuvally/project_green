#!/usr/bin/env python3
# post installation script for Netdog

# import serious stuff
import os
import subprocess
import sys


# execute command
def execute_command(command):
    return_code = subprocess.call(command, shell=True)

    if return_code != 0:
        print(command + " cannot be executed, skipping")


# the main function
def main():
    # create netdog user
    execute_command("adduser --disabled-password --gecos Netdog netdog")

    # add user to sudo group
    execute_command("gpasswd -a netdog sudo")

    # create /share directory
    execute_command("mkdir /share")
    execute_command("chown netdog /share")

    # disable password prompt on sudo
    sudo_file = open("/etc/sudoers.d/netdog", "w")
    sudo_file.write("netdog ALL=(ALL) NOPASSWD:ALL")
    sudo_file.close()


if __name__ == "__main__":
    main()
