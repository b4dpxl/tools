#! /usr/bin/env python3

import json
import sys
import yaml


input = sys.stdin.read().strip()

try:
    j = json.loads(input)
    print(yaml.dump(j))

except Exception as e:
    sys.stderr.write("Error, was that actually JSON?\n")
    print(e)
