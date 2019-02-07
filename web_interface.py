#!/usr/bin/env python3
# NetDog, web interface
# Copyright 2018, 2019 Aswin Babu Karuvally

# import serious stuff
from libgreen import *
from bottle import post, get, static_file, run, request, template

# global variables
command = None
node_list = None


# serve the landing page
@get("/")
def home_page():
    # get config directory
    config_dir = get_config_dir()

    # display the welcome page on first run
    if not os.path.exists(os.path.join(config_dir, "credentials")):
        return static_file("welcome.html", root="static")

    # else return the normal page
    return static_file("index.html", root="static")


# the main function
def start_web_server():
run(host="0.0.0.0", port=9000, debug=True)
