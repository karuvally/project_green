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

# add user netdog to group sudo
