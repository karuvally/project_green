#!/usr/bin/env python3

from libgreen import find_hosts

def call_hosts():
    result = find_hosts({"network_address": "192.168.42.0", "netmask": "255.255.255.0"}, "both")
    return result

