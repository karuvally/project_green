#!/usr/bin/env python3
# NetDog, web interface
# Copyright 2018, 2019 Aswin Babu Karuvally

# import serious stuff
import nacl.pwhash
from libgreen import *
from flask import Flask, render_template, request, make_response, url_for
from flask import redirect
from Crypto.Hash import SHA256


# setup the webapp
web_app = Flask("web_interface")


# monitor clients
@web_app.route("/stats", methods=["GET"])
def system_stats():
    beacon_db = read_beacon_db()

    return render_template(
        "system_stats.html",
        beacon_db = beacon_db
    )


# powersave clients
@web_app.route("/suspend_clients", methods=["GET"])
def suspend_clients():
    # get active clients
    active_clients = get_active_clients()

    # return client chooser page
    return render_template(
        "target_nodes.html", 
        active_clients = active_clients,
        command = "systemctl suspend",
        target_page = "execute_command"
    )


# shutdown clients
@web_app.route("/shutdown_clients", methods=["GET"])
def shutdown_clients():
    # get active clients
    active_clients = get_active_clients()

    if not active_clients:
        return render_template("error_page.html", reason="No active clients!")

    # return client chooser page
    return render_template(
        "target_nodes.html", 
        active_clients = active_clients,
        command = "sudo shutdown -h 0",
        target_page = "execute_command"
    )


# broadcast the file to list of clients
@web_app.route("/exec_broadcast", methods=["POST"])
def exec_broadcast():
    # get broadcast data
    broadcast_data = request.form.to_dict(flat=False)

    print("\n", broadcast_data, "\n") # debug

    # get the file to be broadcasted
    filename = os.listdir("/share")[0]
    broadcast_file = os.path.join("/share", filename)

    print("\n", broadcast_file, "\n") # debug

    # broadcast the files!
    for client in broadcast_data["client"]:
        send_file(broadcast_file, client) 

    # delete the temp file
    os.remove(os.path.join("/share", filename))

    return render_template("index.html") 


@web_app.route("/broadcast", methods=["GET", "POST"])
def gather_broadcast_data():
    # if GET, return file chooser page
    if request.method == "GET":
        return render_template("choose_file.html")

    # if POST, store uploaded file onto tmp dir
    if request.method == "POST":
        data = request.files["upload"]
        filename = data.filename
        data.save(os.path.join("/share", filename))

    active_clients = get_active_clients()

    if not active_clients:
        return render_template("error_page.html", reason="No active clients!")

    return render_template(
        "target_nodes.html",
        active_clients = active_clients,
        target_page = "exec_broadcast"
    )


# start the actual execution of commands
@web_app.route("/execute_command", methods=["POST"])
def execute_command():
    # get execution data
    execution_data = request.form.to_dict(flat=False)
    
    # execute the commands!
    for client in execution_data["client"]:
        send_message(
            port = 1994, 
            command = "execute", 
            payload = execution_data["command"], 
            destination_id = client
        )
        
    return render_template("index.html")


# handle execution of commands
@web_app.route("/gather_exec_data", methods=["POST", "GET"])
def gather_cmd_exec_data():
    # return execute command page on simple GET request
    if request.method == "GET":
        return render_template("execute_command.html")
        
    # get command from user and return client list
    elif request.method == "POST":
        command = request.form["command"]

        active_clients = get_active_clients()
        
        if not active_clients:
            return render_template("error_page.html", reason="No active clients!")
        
        # generate the target clients page
        return render_template(
            "target_nodes.html", 
            active_clients = active_clients,
            command = command,
            target_page = "execute_command"
        )
        

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
    web_app.run(debug = False, port=9000, host="0.0.0.0")
