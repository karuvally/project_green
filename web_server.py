#!/usr/bin/env python3
# NetDog Web Server, alpha release
# Copyright 2018, Aswin Babu Karuvally

# import serious stuff
from libgreen import *
from bottle import route, run, template


# default page
@route("/")
def home_page():
    return("Hello")


# the main function
def start_web_server():
    run(host = "0.0.0.0", port = 9000, debug = True)
