#!/usr/bin/env python3

"""dkim_key_length_check.py: Pull DKIM records from DNS and validate the RSA key length"""
__author__ = "b4dpxl"
__credits__ = [ "https://protodave.com/" ]
__license__ = "GPL"
__version__ = "1.0.0"


import dns.resolver
import re
import argparse
from OpenSSL import crypto

class printer:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    def ok(self, str):
        self.print_col( "[+]", str, self.OKGREEN)

    def info(self, str):
        self.print_col( "[*]", str, self.OKBLUE)

    def warn(self, str):
        self.print_col( "[-]", str, self.WARNING)

    def error(self, str):
        self.print_col( "[!]", str, self.FAIL)

    def print_col(self, str1, str2, col):
        print("%s%s%s %s" % (col, str1, self.ENDC, str2))

    def default(self, str):
        print(str)

def get_key_length( _key ):
    pub_key = crypto.load_publickey( crypto.FILETYPE_PEM, ( "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----" % _key ).encode() )
    return pub_key.bits()

def main():

    parser = argparse.ArgumentParser( description='DKIM Key Length Checker' )
    parser.add_argument('--domain', '-d', help='Enter the Domain name to verify. E.g. pxl.me.uk', required=True )
    parser.add_argument('--selector', '-s', help='Enter the Selector to verify [default]', required=False, default="default" )
    args = parser.parse_args()

    domain_key = "%s._domainkey.%s" % ( args.selector, args.domain )

    printer().info( "Checking DKIM entry for %s" % domain_key )

    txt_list = []
    try:
        for txt in dns.resolver.query( domain_key, 'TXT').response.answer:
            txt_list.append( txt )
    except:
        printer().error( "No TXT records exist for %s" % domain_key )

    try:
        for txt in txt_list:
            str_txt = txt.to_text()
            # handle long records - TXT records are max 255 chars, split into multiple parts after that
            if len( str_txt ) > 257:
                str_txt = re.sub( """\"\s+\"""", "", str_txt )
            if "k=rsa" in str_txt and "p=" in str_txt:
                rsa = re.search( """p=([\w\/\+]+)\\b""", str_txt ).group(1)
                printer().info( "RSA key: %s" % rsa )
                key_len = get_key_length( rsa )
                printer().ok( "Key length for %s is %d bits" % ( args.domain, key_len ) )
            else:
                printer().warn( "No valid TXT entries for %s" % domain_key )
    except:
        printer().error( "Unable to parse TXT records" )

main()
