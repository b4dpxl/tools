#! /bin/env python3
"""
mimikatz_parser.py: Parse Invoke-Mimikatz.ps1 files, extracting usernames and hashes

Requirements:
pip3 install python-dateutil

History:
0.1 - First release
0.2 - Should now extract SSP and credman creds associated to a user
"""
__author__ = "b4dpxl"
__license__ = "GPL"
__version__ = "0.2"


import argparse
import csv
import codecs
import os
import re
import sys
from dateutil import tz, parser
try:
    from __printer import Printer
except:
    print("ERROR: Please download __printer.py from https://raw.githubusercontent.com/b4dpxl/tools/master/__printer.py")
    sys.exit(1)



printer = Printer(debug=False, trace=False)

users_to_ignore = [
    "(null)",
    "local service",
    "iusr"
]

re_user_name = r"^User Name +: +([^\$]+)$"
re_domain = r"^Domain +: +(.*)$"
re_logon_time = r"^Logon Time +: +(.*)$"

re_state = r"\b(msv|tspkg|wdigest|kerberos|ssp|credman) +:"
re_username = r"\* Username +: +(.*)$"

re_ntlm = r"\* NTLM +: +(.*)$"
re_password = r"\* Password +: +(.*)$"
re_domain2 = r"\* Domain +: +(.*)$"


def enumerate_dirs(dir, users_array, utf8=False):
    print("Checking {}".format(dir))
    for filename in os.listdir(dir):
        if filename.endswith(".txt"):
            parse_file("{}/{}".format(dir, filename), users_array, utf8)


def parse_file(filename, users_array, utf8=False):
    printer.info("Checking {}".format(filename))

    is_newer = False
    in_user = False
    current_user = None
    current_username = None
    state = None
    current_logon_time = None

    encoding = 'utf-16-le'
    if utf8:
        encoding = 'utf-8'

    with codecs.open(filename, 'r', encoding) as f:
        for line in [x.strip() for x in f.readlines()]:

            if re.search(r"^Authentication Id +:", line):
                in_user = True

            if in_user and re.search(re_user_name, line):
                current_username = re.match(re_user_name, line)[1].lower()
                if current_username not in users_to_ignore:
                    printer.debug("Found {}".format(current_username))
                    if not any(x["username"] == current_username for x in users_array):
                        printer.trace("New user")
                        current_user = {"username": current_username}
                        users_array.append(current_user)
                        is_newer = True
                        current_logon_time = None
                    else:
                        printer.trace("Existing user")
                        current_user = next(x for x in users_array if x["username"] == current_username)
                        if "logon_time" in current_user.keys():
                            current_logon_time = parser.parse(current_user["logon_time"])
                else:
                    current_user = None
                    current_username = None
                    is_newer = False

            if in_user and current_user is not None:
                if re.search(re_domain, line):
                    current_user["domain"] = re.match(re_domain, line)[1]

                if re.search(re_logon_time, line):
                    # TODO check the logon time is newer than anything already found
                    t = re.match(re_logon_time, line)[1]
                    new_logon_time = parser.parse(t)
                    if current_logon_time is None or new_logon_time > current_logon_time:
                        current_logon_time = new_logon_time
                        current_user["logon_time"] = t
                        is_newer = True
                        printer.trace("Newer logon time")
                    else:
                        printer.trace("Older logon time")
                        is_newer = False

                if re.search(re_state, line):
                    state = re.match(re_state, line)[1]
                    printer.trace(state)
                    state_username = None

                if re.search(re_username, line):
                    su = re.match(re_username, line)[1].lower()
                    # if su == current_user["username"]:
                    state_username = su
                    if "\\" in state_username:
                        state_username = state_username.split('\\')[1]
                    state_domain = None
                    printer.trace(state_username)

                if is_newer:
                    if re.search(re_ntlm, line) and state == "msv" and state_username is not None:
                            current_user["ntlm"] = re.match(re_ntlm, line)[1]

                    if re.search(re_password, line) and state == "wdigest" and state_username is not None:
                            current_user["wdigest"] = re.match(re_password, line)[1]

                if state == "ssp" or state == "credman":
                    if state_username is not None and state_username != current_username:
                        if re.search(re_domain2, line):
                            state_domain = re.match(re_domain2, line)[1]
                            if "\\" in state_domain:
                                state_domain = state_domain.split('\\')[0]

                        if re.search(re_password, line):
                            pwd = re.match(re_password, line)[1]
                            if not any(x["username"] == state_username and x["domain"] == state_domain for x in users_array):
                                printer.trace("New user, SSP or credman")
                                users_array.append({"username": state_username, "domain": state_domain, state: pwd})
                            else:
                                printer.trace("Existing user, SSP or credman")
                                tmp_user = next(x for x in users_array if x["username"] == state_username and x["domain"] == state_domain)
                                tmp_user[state] = pwd



def main():
    arg_parser = argparse.ArgumentParser("Mimikatz output parser")
    group = arg_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", help="Directory containing file", dest="dir")
    group.add_argument("-f", help="Mimikatz output file", dest="file")
    arg_parser.add_argument("-o", help="Output file (csv)", dest="output", required=False)
    arg_parser.add_argument("--utf8", dest="utf8", help="For UTF-8 formatted files. PowerShell default is UTF-16. Needed if you've done unix2dos, iconv, or similar on the files", required=False, action="store_true")
    args = arg_parser.parse_args()

    users = []
    if args.file:
        parse_file(args.file, users, args.utf8)
    else:
        enumerate_dirs(args.dir, users, args.utf8)

    if not args.output:
        print(users)
    else:
        with open(args.output, 'w') as out:
            writer = csv.DictWriter(out, fieldnames=['username', 'domain', 'logon_time', 'ntlm', 'wdigest', 'ssp', 'credman'], quoting=csv.QUOTE_ALL)
            writer.writeheader()
            for user in users:
                writer.writerow(user)
        pass


main()