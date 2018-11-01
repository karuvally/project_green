#!/usr/bin/env python3
# NetDog Web Server, alpha release
# Copyright 2018, Aswin Babu Karuvally

# import serious stuff
from libgreen import *
from bottle import post, route, static_file, run

# serve the images 
@route("/assets/<image_file>")
def serve_css(image_file):
    return static_file(image_file, root="html/assets")


# serve the CSS
@route("/css/<css_file>")
def serve_css(css_file):
    return static_file(css_file, root="html/css")


# serve the landing page
@route("/")
def home_page():
    return static_file("home.html", root="html")


# the main function
def start_web_server():
    run(host="0.0.0.0", port=9000, debug=True)
