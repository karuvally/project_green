#!/usr/bin/env python3
# clear NetDog configuration
# Copyright 2018, Aswin Babu Karuvally

# import serious stuff
from libgreen import get_config_dir
import shutil

# get config directory path
config_dir = get_config_dir()

# do the stuff
if os.path.exists(config_dir):
    shutil.rmtree(config_dir)
else:
    print("configuration directory does not exist!")

