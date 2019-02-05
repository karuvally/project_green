#!/usr/bin/env python3
# NetDog, web interface
# Copyright 2018, 2019 Aswin Babu Karuvally

# import serious stuff
from libgreen import *
from flask import Flask


# create the webapp
app = Flask(__name__)


# the homepage
@app.route("/")
def landing_page():
    return "It Works!"


# run the webapp
app.run()
