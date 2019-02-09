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

    # else return the normal page
    return static_file("index.html", root="html")
    
    
# serve the stylesheets
@get("/css/<css_file>")
def retrieve_stylesheets(css_file):
    return static_file(css_file, root="html/css")
    

# serve the assets
@get("/assets/<asset_file>")
def retrieve_assets(asset_file):
    return static_file(asset_file, root="html/assets")


# the main function
def start_web_server():
    run(host="localhost", port=9000, debug=True)
