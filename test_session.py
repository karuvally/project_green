#!/usr/bin/env python3
# bottle-session test script

# import the serious stuff
import bottle_session
import bottle
from bottle import install, get, run


# serve the homepage
@get("/")
def serve_home(session):
    username = session.get("username")
    
    if username != None:
        return(username, " it works :D")


# set username
@get("/set/<username>")
def set_username(session, username):
    session["username"] = username
    

# run the app
def run_server():
    # setup the plugins
    plugin = bottle_session.SessionPlugin(cookie_lifetime=None)
    install(plugin)
    
    run(host="localhost", port=9000, debug=True)
