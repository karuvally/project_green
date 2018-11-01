#!/usr/bin/env python3
# NetDog Web Server, alpha release
# Copyright 2018, Aswin Babu Karuvally

# import serious stuff
from libgreen import *
from bottle import post, get, run


# default page
@get("/")
def home_page():
    return("Hello")


# the main function
def start_web_server():
    run(host = "0.0.0.0", port = 9000, debug = True)
