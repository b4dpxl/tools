#! /usr/bin/env python3

import json
import sys


input = sys.stdin.read().strip()

try:
    j = json.loads(input)
    print(json.dumps(j, indent=2))

except Exception as e:
    sys.stderr.write("Error, was that actually JSON?\n")
    print(e)

