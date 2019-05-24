#!/usr/bin/env python3
# post installation script for Netdog

# import serious stuff
import os
import subprocess


# create desktop shortcut
def desktop_shortcut(target):
    for home_dir in os.listdir("/home"):
        if home_dir == "lost+found":
            continue

        shortcut_path = os.path.join("/home", home_dir, "Desktop")
        execute_command("ln -s /share " + shortcut_path)


# execute command
def execute_command(command):
    return_code = subprocess.call(command, shell=True)

    if return_code != 0:
        logging.warning(command + " cannot be executed, exiting")
        sys.exit(1)


# the main function
def main():
    # install conky
    execute_command("apt-get install conky-cli")

    # create netdog user
    execute_command("adduser --disabled-password --gecos Netdog netdog")

    # add user to sudo group
    execute_command("gpasswd -a netdog sudo")

    # disable password prompt on sudo
    sudo_file = open("/etc/sudoers.d/netdog")
    sudo_file.write("netdog ALL=(ALL) NOPASSWD:ALL")
    sudo_file.close()

    # create share dir and create shortcut
    execute_command("mkdir /share")
    execute_command("chown netdog /share")
    desktop_shortcut("/share")


if __name__ == "__main__":
    main()
