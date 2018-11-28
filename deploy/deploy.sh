#!/bin/bash
# deploy NetDog client
# Copyright 2018, Aswin Babu Karuvally

# exit if not root
USERNAME=`whoami`
if [ $USERNAME != "root" ]
then
    echo "run script as root!"
    exit
fi

# create user netdog
adduser --disabled-password --gecos "NetDog User" netdog

# set password for netdog
echo "netdog:netdog" | chpasswd

# add user netdog to group sudo
gpasswd -a netdog sudo
