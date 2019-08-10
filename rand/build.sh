#!/bin/bash

echo deleting existing files
rm /home/aswin/tmp/deploy_it -rf

echo copying new files
cp /home/aswin/project/deploy_it /home/aswin/tmp/ -rf
cp /home/aswin/project/netdog/src /home/aswin/tmp/deploy_it -rf

echo trying to build the package
cd /home/aswin/tmp/deploy_it
./build.py

echo extracting the builds from zip
rm ../builds/* -rf
cd ../builds
unzip ../deploy_it/netdog_server.zip
unzip ../deploy_it/netdog_clients.zip
