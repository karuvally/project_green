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
    return static_file("index.html", root="static")


# the main function
def start_web_server():
run(host="0.0.0.0", port=9000, debug=True)
