#!/usr/bin/env python3
# test partial dictionary update

# import the serious stuff
import collections


sample_dict = {
    "name": "Aswin",
    "age": 24,
    "marks": {
        "python": 50,
        "maths": 45
    }
}


def update(original, new):
    for key, value in new.items():
        if isinstance(value, collections.Mapping):
            original[key] = update(original.get(key, {}), value)
        else:
            original[key] = value
    return original
