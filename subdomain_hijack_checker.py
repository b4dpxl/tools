#! /usr/bin/env python3

import argparse
import fileinput
import sys

from dns.exception import DNSException
from dns.resolver import Answer, Resolver

try:
    from __printer import Printer
except:
    print("ERROR: Please download __printer.py from https://raw.githubusercontent.com/b4dpxl/tools/master/__printer.py")
    sys.exit(1)

__version__ = "0.0.1"

parser = argparse.ArgumentParser(description="Subdomain hijack enumerator")
parser.add_argument("-v", "--verbose", dest="verbose", help="Verbose output", required=False, action="store_true")
parser.add_argument('--version', '-V', action='version', version='%(prog)s {}'.format(__version__))
parser.add_argument(dest='files', help="Input file(s), or - for stdin", nargs='*')
args = parser.parse_args()

printer = Printer(debug=args.verbose)

resolver = Resolver()

for domain in [x.strip() for x in fileinput.input(files=args.files)]:
    try:
        answers: Answer = resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            target = str(rdata.target).lower()
            printer.info(f"{domain} is a CNAME of {target}")
            try:
                printer.debug(f"{domain} resolves to {resolver.resolve(target)[0]}")
            except DNSException:
                printer.warn(f"target {target[:-1]} of CNAME {domain} is dangling!")
                if ".s3." in target and ".amazonaws.com" in target:
                    printer.error(f"{target} is an Amazon s3 bucket!!")

                elif ".storage.googleapis.com" in target:
                    printer.error(f"{target} is a Google Cloud Storage bucket!!")

                elif ".azurewebsites.net" in target:
                    printer.error(f"{target} is an Azure website!!")

    except DNSException:
        printer.debug(f"{domain} is not a CNAME")
        pass
