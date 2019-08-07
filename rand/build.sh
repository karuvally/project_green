#!/bin/bash

# delete existing files
rm /home/aswin/tmp/deploy_it -r -v

# copy new files 
cp /home/aswin/project/deploy_it /home/aswin/tmp/ -r -v
cp /home/aswin/project/netdog/src /home/aswin/tmp/ -r -v

# try building the package
cd /home/aswin/tmp/deploy_it
