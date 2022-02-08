#! /usr/bin/env python3

"""
Generate various permutations of username for a given first and last name.
"""

import argparse

parser = argparse.ArgumentParser(description="Username generator")
parser.add_argument("-f", "--first", dest="first", help="First name", required=True)
parser.add_argument("-l", "--last", dest="last", help="Last name", required=True)
args = parser.parse_args()

fn = args.first.lower()
sn = args.last.lower()
init = fn[0]
init2 = fn[0:1]

usernames = [
    f"{fn}.{sn}",
    f"{fn}{sn}",
    f"{init}.{sn}",
    f"{init}{sn}",
    f"{init2}.{sn}",
    f"{init2}{sn}",
    f"{sn}.{fn}",
    f"{sn}{fn}",
    f"{sn}.{init}",
    f"{sn}{init}",
    f"{sn}.{init2}",
    f"{sn}{init2}",
    f"{fn}{sn[0]}",
    f"{init}{sn[0:1]}"
]

extended_usernames = [
    f"{sn}1{init}",
    f"{sn}01{init}",
    f"{sn}001{init}"
]

for username in usernames:
    print(username)
    print(f"{username}1")
    print(f"{username}01")
print("\n".join(extended_usernames))


