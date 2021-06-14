#! /usr/bin/env python3

import argparse
import json
import sys

from pathlib import Path
from termcolor import colored, cprint

parser = argparse.ArgumentParser(description="Swagger/OpenAPI endpoint parser")
parser.add_argument("-v", "--verbose", dest="verbose", help="Verbose output", required=False, action="store_true")
parser.add_argument(dest="file", help="Input File(s)", nargs='+')
args = parser.parse_args()

VERBS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']    

for f in args.file:
    p = Path(f)
    if not p.exists() and not p.is_file():
        cprint(f"[!]  Invalid file: {f}", 'red', attrs=['bold'], file=sys.stderr)
        continue

    i=0
    with open(f, 'r') as f2:
        swagger = json.load(f2)

        if swagger.get('paths'):
            print(f"{colored('[+]', 'green', attrs=['bold'])}  {colored(f, 'blue', attrs=['bold', 'underline'])}")
            for path, obj in sorted(swagger['paths'].items()):
                    for method in obj:
                        if method.upper() in VERBS:
                            i = i+1
                            print(f"{i:>4} {method.upper():>6} {path}") 

    print()

