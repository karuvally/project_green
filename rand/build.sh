#!/bin/bash

echo deleting existing files
rm /home/aswin/tmp/deploy_it -rf

echo copying new files
cp /home/aswin/project/deploy_it /home/aswin/tmp/ -rf
cp /home/aswin/project/netdog/src /home/aswin/tmp/deploy_it -rf
cd /home/aswin/tmp/deploy_it

echo building netdog client 
cp src/deploy/netdog_client/config.json ./
./build.py

echo building netdog server 
cp src/deploy/netdog_server/config.json ./
./build.py

echo extracting the builds from zip
if [ ! -d ../builds ]; then
    mkdir ../builds
else
    rm ../builds/* -rf
fi
cd ../builds
unzip ../deploy_it/netdog_server.zip
unzip ../deploy_it/netdog_clients.zip
