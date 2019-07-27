#!/usr/bin/env python3
# cleanup leftovers when uninstalling

# import the serious stuff
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
    # remove conky
    execute_command("apt-get remove conky-cli -y")

    # remove netdog user
    execute_command("deluser --remove-all-files netdog")

    # remove sudoer file
    # remove share directory


if __name__ == "__main__":
    main()
