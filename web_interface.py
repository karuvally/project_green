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
    
    # if first run, return welcome page
    if not os.path.exists(os.path.join(config_dir, "passwd")):
        return static_file("welcome.html", root="html")

    # else return the normal page
    return static_file("index.html", root="html")
    

# serve the rest of the pages
@get("/<html_file>")
def retrieve_page(html_file):
    return static_file(html_file, root="html")
    
    
# serve the stylesheets
@get("/css/<css_file>")
def retrieve_stylesheets(css_file):
    return static_file(css_file, root="html/css")
    

# serve the assets
@get("/assets/<asset_file>")
def retrieve_assets(asset_file):
    return static_file(asset_file, root="html/assets")
    

# create a new account for user
@post("/signup.html")
def create_account():
    # get the form data
    full_name = request.forms.get("full_name")
    username = request.forms.get("username")
    password = request.forms.get("password")
    
    # generate hash of username, password
    
    # write data to passwd file


# the main function
def start_web_server():
    run(host="localhost", port=9000, debug=True)
