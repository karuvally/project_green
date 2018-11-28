#!/usr/bin/env python3

from libgreen import *

network = probe_interfaces()

find_hosts(network["enp0s25"], "both")
