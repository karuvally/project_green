#!/usr/bin/env python3

import signal
import sys

def signal_handler(signal, frame):
    print("exiting...")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)

    while True:
        input(">")


main()
