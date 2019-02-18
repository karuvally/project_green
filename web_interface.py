#!/usr/bin/env python3
# NetDog, web interface
# Copyright 2018, 2019 Aswin Babu Karuvally

# import serious stuff
from libgreen import *
from flask import Flask, render_template, request


# setup the webapp
web_app = Flask("web_interface")


# serve the landing page
@web_app.route("/", methods=["GET"])
def home_page():
    # get config directory
    config_dir = get_config_dir()
    
    # if first run, return welcome page
    if not os.path.exists(os.path.join(config_dir, "passwd")):
        return render_template("welcome.html")

    # else return the normal page, debug
    else:
        return render_template("login.html")


"""
# create a new account for user
@web_app.route("/signup.html", methods=["POST"])
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
    
    # return the login page
    return static_file("login.html", root="html")
"""


# handle the login
@web_app.route("/login.html", methods=["POST"])
def handle_login():
    # get the stored user data
    user_data = read_configuration("passwd")
    
    # get the form data
    username = request.form["username"]
    password = request.form["password"]
    
    # generate hash of username and password
    username_hash = SHA256.new(username.encode()).hexdigest()
    password_hash = SHA256.new(password.encode()).hexdigest()
    
    # check login details and set cookie
    if user_data["username"] == username_hash:
        if user_data["password"] == password_hash:
            return render_template("index.html")
            
    # return the error page otherwise
    return render_template("login_error.html")


# the main function
def start_web_server():
    # run the webserver
    web_app.run(
        debug = True,
    )
