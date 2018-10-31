#!/usr/bin/env python3
# NetDog Web Server, alpha release
# Copyright 2018, Aswin Babu Karuvally

# import serious stuff
from bottle import route, run, template


# default page
@route("/")
def index():
    return("Hello")


# the main function
def main():
    run(host = "0.0.0.0", port = 8080)
