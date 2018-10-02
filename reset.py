#!/usr/bin/env python3
# clear NetDog configuration
# Copyright 2018, Aswin Babu Karuvally

# import serious stuff
from libgreen import get_config_dir
import shutil

# do the stuff
shutil.rmtree(get_config_dir())

