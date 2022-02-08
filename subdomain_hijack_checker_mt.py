#! /usr/bin/env python3

import argparse
import fileinput
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

printer = Printer()

def main():
    parser = argparse.ArgumentParser(description="Subdomain hijack enumerator")
    parser.add_argument("-t", "--threads", dest="threads", help="Number of threads [5]", required=False, type=int, default=5)
    parser.add_argument("-v", "--verbose", dest="verbose", help="Verbose output", required=False, action="store_true")
    parser.add_argument('--version', '-V', action='version', version='%(prog)s {}'.format(__version__))
    parser.add_argument(dest='files', help="Input file(s), or - for stdin", nargs='*')
    args = parser.parse_args()
    if not args.files:
        parser.print_usage()
        sys.exit(1)

    printer._debug_on = args.verbose

    if args.files[0] == '-':
        printer.debug("Reading files from stdin")

    threads = []

    c = 0
    for domain in [x.strip() for x in fileinput.input(files=args.files)]:
        while threading.active_count() > args.threads:  # there is always at least one thread (main) 
            time.sleep(1)

        c += 1
        thread = threading.Thread(target=check_domain, args=[domain])  # , f"({c}) "
        threads.append(thread)
        thread.start()

def check_domain(domain, thread_id=""):
    try:
        resolver = Resolver()
        answers: Answer = resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            target = str(rdata.target).lower()
            printer.info(f"{thread_id}{domain} is a CNAME of {target}")
            try:
                printer.debug(f"{thread_id}{domain} resolves to {resolver.resolve(target)[0]}")
            except DNSException:
                printer.warn(f"{thread_id}target {target[:-1]} of CNAME {domain} is dangling!")
                if ".s3." in target and ".amazonaws.com":
                    printer.error(f"{thread_id}{target} is an Amazon s3 bucket!!")

                elif ".storage.googleapis.com" in target:
                    printer.error(f"{thread_id}{target} is a Google Cloud Storage bucket!!")

                elif ".azurewebsites.net" in target:
                    printer.error(f"{thread_id}{target} is an Azure website!!")

    except DNSException:
        printer.debug(f"{thread_id}{domain} is not a CNAME")
        pass


if __name__ == "__main__":
    main()

