#!/usr/bin/env python3
# NetDog Web Server, alpha release
# Copyright 2018, Aswin Babu Karuvally

# import serious stuff
from libgreen import *
from bottle import post, get, static_file, run, request

# global variables
command = None
node_list = None


# store the command from user, return node selection page
@post("/submit_command")
def node_list():
    # get the command from user
    command = request.forms.get("command")

    # get known nodes
    known_nodes = read_configuration("known_nodes")

    # generate the node list page
    return template("select_nodes", known_nodes)


# serve the command input page
@get("/execute.html")
def serve_execute_page():
    return static_file("execute.html", root="html")


# serve the images 
@get("/assets/<image_file>")
def serve_css(image_file):
    return static_file(image_file, root="html/assets")


# serve the CSS
@get("/css/<css_file>")
def serve_css(css_file):
    return static_file(css_file, root="html/css")


# serve the landing page
@get("/")
def home_page():
    return static_file("home.html", root="html")


# the main function
def start_web_server():
    run(host="0.0.0.0", port=9000, debug=True)
