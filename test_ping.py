#!/usr/bin/env python3

from libgreen import *

host_info = []
node_list = []
ping_threads = []
checker_threads = []
port_list = [1337, 1994]

network_info = probe_interfaces()["enp0s20u1"]

# generate the cidr address
cidr_address = netaddr.IPNetwork(network_info["network_address"],
    network_info["netmask"])

network = ipaddress.ip_network(cidr_address)

for ip_address in network.hosts():
    ping_thread = threading.Thread(target = ping_sweep,
        args = (ip_address, host_info))

    ping_threads.append(ping_thread)
    ping_thread.start()

# wait until all threads are finished
for thread in ping_threads:
    thread.join()

# generate list of online hosts
online_hosts = [host for host in host_info if host["online"] == True]

# find local host's IP
localhost_address = network_info["localhost_address"]

# remove localhost from online_hosts
online_hosts = [host for host in online_hosts
    if str(host["ip_address"]) != localhost_address]

# check if the host is a netdog client/server
for host in online_hosts:
    checker_thread = threading.Thread(target = check_if_node,
        args = [host, port_list, node_list])

    checker_threads.append(checker_thread)
    checker_thread.start()

# wait for threads to finish
for thread in checker_threads:
    thread.join()

