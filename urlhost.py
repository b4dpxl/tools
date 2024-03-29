#! /usr/bin/env python3

"""
urlhost.py

Acts as the Linux `host` command, but accepts URLs. Useful for copy/pasting from a browser

Requirements: 
    dnspython
"""

import argparse
import sys

from dns import resolver
from urllib.parse import urlparse

def main():

    parser = argparse.ArgumentParser(description="URL Domain Resolver")
    parser.add_argument(dest="url", help="URL to parse")
    args = parser.parse_args()

    url = urlparse(args.url)
    if not url.netloc:
        domain = url.path.split("/")[0]
    else:
        domain = url.netloc

    # check if it's a CNAME first
    domain = get_domain_from_cname(domain)

    try:
        results = resolver.resolve(domain, 'A')
        for result in results:
            print(f"{domain} has address {result.to_text()}")
    except resolver.NoAnswer:
        print(f"Unable to resolve {domain}")
    except resolver.NXDOMAIN:
        print(f"Host {domain} not found: 3(NXDOMAIN)")


def get_domain_from_cname(domain, depth=1, max_depth=3):
    try:
        cnames = resolver.resolve(domain, 'CNAME')
        if cnames:
            print(f"{domain} is an alias for {cnames[0].target}")
            domain = cnames[0].target.to_text()
            if domain.endswith("."):
                domain = domain[:-1]
                if depth >= max_depth:
                    sys.stderr.write(f"\033[91mToo many recursions, using domain as-is\033[0m\n")
                    return domain
            return get_domain_from_cname(domain)
    
    except (resolver.NXDOMAIN, resolver.NoAnswer):
        # not a CNAME
        return domain

main()
