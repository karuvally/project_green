#!/usr/bin/env python3
# NetDog, web interface
# Copyright 2018, 2019 Aswin Babu Karuvally

# import serious stuff
from libgreen import *
from flask import Flask, render_template, request, make_response, url_for
from flask import redirect


# setup the webapp
web_app = Flask("web_interface")


# handle execution of commands
@web_app.route("/command", methods=["POST", "GET"])
def handle_command_execution():
    # return execute command page on simple GET request
    if request.method == "GET":
        return render_template("execute_command.html")
        
    # get command from user and return client list
    elif request.method == "POST":
        command = request.form["command"]
        # debug, return client list, complete beacon system first


# accept the choosen interface
@web_app.route("/submit_interface", methods=["POST"])
def submit_interface():
    # get the user selected interface
    chosen_interface = request.form["interface"]
    
    # get the network info from interface
    network_info = probe_interfaces()[chosen_interface]
    
    # write the information gathered to known_network
    write_configuration(network_info, "known_network")
    
    # return the homepage
    return render_template("index.html")


# serve the landing page
@web_app.route("/", methods=["GET"])
def home_page():
    # get config directory
    config_dir = get_config_dir()
    
    # get the cookie
    username = request.cookies.get("username")
    
    # if first run, return welcome page
    if not os.path.exists(os.path.join(config_dir, "passwd")):
        return render_template("welcome.html")

    # if not logged in return login page
    elif not username:
        return render_template("login.html")
        
    # if no known_network, return network chooser
    elif not os.path.exists(os.path.join(config_dir, "known_network")):
        return render_template(
            "network_chooser.html",
            interface_dump=probe_interfaces()
        )
    
    # else, simply return the homepage
    else:
        return render_template("index.html")


# create a new account for user
@web_app.route("/signup.html", methods=["GET", "POST"])
def create_account():
    # if GET, return the signup page
    if request.method == "GET":
        return render_template("signup.html")
    
    # empty dictionary to store user info
    user_data = {}
    
    # get the form data
    full_name = request.form["full_name"]
    username = request.form["username"]
    password = request.form["password"]
    
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
    return render_template("login.html")


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
            home_page = make_response(redirect(url_for("home_page")))
            home_page.set_cookie("username", username_hash)
            return home_page
            
    # return the error page otherwise
    return render_template("login_error.html")


# the main function
def start_web_server():
    # run the webserver
    web_app.run(
        debug = True,
    )
