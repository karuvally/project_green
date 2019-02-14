#!/usr/bin/env python3

# import serious stuff
from bottle import response, get, run, request


@get("/")
def main_page():
    cookie_data = request.get_cookie("name")
    
    if cookie_data:
        return cookie_data

run(host="localhost", port=9000)
