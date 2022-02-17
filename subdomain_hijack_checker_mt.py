#! /usr/bin/env python3

import argparse
import fileinput
from hashlib import new
import sys
import threading
import time

from dns.exception import DNSException
from dns.resolver import Answer, Resolver

try:
    from __printer import Printer
except:
    print("ERROR: Please download __printer.py from https://raw.githubusercontent.com/b4dpxl/tools/master/__printer.py")
    sys.exit(1)

__version__ = "0.0.1"

printer = Printer(dark=True)

def main():
    parser = argparse.ArgumentParser(description="Subdomain hijack enumerator")
    parser.add_argument('-t', '--threads', dest='threads', help="Number of threads [5]", required=False, type=int, default=5)
    parser.add_argument('--ns', dest='name_server', help="Name server to use instead of the default system nameserver", required=False, default=None)
    parser.add_argument('-v', '--verbose', dest='verbose', help="Verbose output", required=False, action='store_true')
    parser.add_argument('-vv', '--veryverbose', dest='very_verbose', help="Very verbose output", required=False, action='store_true')
    parser.add_argument('--version', '-V', action='version', version='%(prog)s {}'.format(__version__))
    parser.add_argument(dest='files', help="Input file(s), or - for stdin", nargs='*')
    args = parser.parse_args()
    if not args.files:
        parser.print_usage()
        sys.exit(1)

    printer._debug_on = args.verbose or args.very_verbose
    printer._trace_on = args.very_verbose

    line_count = 0
    if args.files[0] == '-':
        printer.debug("Reading files from stdin")
    else:
        for f in args.files:
            with open(f, 'rb') as f2:
                for i, _ in enumerate(f2.readlines()):
                    pass
            line_count += i + 1
    

    if line_count:
        ns = f" using name server {args.name_server}" if args.name_server else ""
        printer.info(f"Checking {line_count} records in {args.threads} threads{ns}")

    threads = []

    c = 0

    for domain in [x.strip() for x in fileinput.input(files=args.files)]:
        if not domain or domain.startswith('#'):
            continue
        while threading.active_count() > args.threads:  # there is always at least one thread (main) 
            time.sleep(1)

        c += 1
        thread = threading.Thread(target=check_domain, args=[domain, args.name_server, ""])  # , f"({c}) "
        threads.append(thread)
        thread.start()
        if line_count and c % min(line_count / 10, 100) == 0:
            end = '\n' if printer._debug_on else '\r'
            sys.stderr.write(f"Progress: {c}/{line_count} {round(100 / line_count * c, 1)}%{end}")

def check_domain(domain, name_server=None, thread_id=""):
    try:
        resolver = Resolver()
        if name_server is not None:
            resolver.nameservers = [name_server]
        answers: Answer = resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            target = str(rdata.target).lower()
            try:
                printer.debug(f"{thread_id}{domain} is a CNAME of {target}")
                printer.trace(f"{thread_id}{domain} resolves to {resolver.resolve(target)[0]}")
            except DNSException:
                printer.ok(f"{thread_id}target {target[:-1]} of CNAME {domain} is dangling!")
                if ".s3." in target and ".amazonaws.com":
                    printer.error(f"{thread_id}{target} is an Amazon s3 bucket!!")

                elif ".storage.googleapis.com" in target:
                    printer.error(f"{thread_id}{target} is a Google Cloud Storage bucket!!")

                elif ".azurewebsites.net" in target:
                    printer.error(f"{thread_id}{target} is an Azure website!!")

    except DNSException:
        printer.debug(f"{thread_id}{domain} is not a CNAME")


if __name__ == "__main__":
    main()

