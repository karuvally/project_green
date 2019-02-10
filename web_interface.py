#!/usr/bin/env python3
# NetDog, web interface
# Copyright 2018, 2019 Aswin Babu Karuvally

# import serious stuff
from libgreen import *
from bottle import post, get, static_file, run, request, template, install
import bottle_session


# serve the landing page
@get("/")
def home_page():
    # get config directory
    config_dir = get_config_dir()
    
    # if first run, return welcome page
    if not os.path.exists(os.path.join(config_dir, "passwd")):
        return static_file("welcome.html", root="html")

    # else return the normal page, debug
    return static_file("login.html", root="html")
    

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
    # empty dictionary to store user info
    user_data = {}
    
    # get the form data
    full_name = request.forms.get("full_name")
    username = request.forms.get("username")
    password = request.forms.get("password")
    
    # generate hash of username, password
    username_hash = SHA256.new(username.encode()).hexdigest()
    password_hash = SHA256.new(password.encode()).hexdigest()
    
    # insert processed data to dictionary
    user_data.update({"full_name": full_name})
    user_data.update({"username": username_hash})
    user_data.update({"password": password_hash})
    
    # write data to passwd file
    update_configuration(config=user_data, filename="passwd", force=True)
    

# handle the login
@post("/login.html")
def handle_login(session):
    # get the stored user data
    user_data = read_configuration("passwd")
    
    # get the form data
    username = request.forms.get("username")
    password = request.forms.get("password")
    
    # generate hash of username and password
    username_hash = SHA256.new(username.encode()).hexdigest()
    password_hash = SHA256.new(password.encode()).hexdigest()
    
    # set session and return homepage if submitted data is correct
    if user_data["username"] == username_hash:
        if user_data["password"] == password_hash:
            session["username"] = username_hash
            return static_file("index.html", root="html")
            
    # return the error page otherwise
    return static_file("login_error.html", root="html")
    

# the main function
def start_web_server():
    run(host="localhost", port=9000, debug=True)
