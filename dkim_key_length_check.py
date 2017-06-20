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

def get_key_length( _key ):
    pub_key = crypto.load_publickey( crypto.FILETYPE_PEM, ( "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----" % _key ).encode() )
    return pub_key.bits()

def main():

    parser = argparse.ArgumentParser( description='DKIM Key Length Checker' )
    parser.add_argument('--domain', '-d', help='Enter the Domain name to verify. E.g. pxl.me.uk', required=True )
    parser.add_argument('--selector', '-s', help='Enter the Selector to verify [default]', required=False, default="default" )
    args = parser.parse_args()

    txt_list = []
    try:
        for txt in dns.resolver.query( "%s._domainkey.%s" % ( args.selector, args.domain ), 'TXT').response.answer:
            txt_list.append( txt )
    except:
        print( "[!] No TXT records exist for %s._domainkey.%s" % ( args.selector, args.domain ) )

    try:
        for txt in txt_list:
            str_txt = txt.to_text()
            # handle long records - TXT records are max 255 chars, split into multiple parts after that
            if len( str_txt ) > 257:
                str_txt = re.sub( """\"\s+\"""", "", str_txt )
            if "v=DKIM1" in str_txt and "p=" in str_txt:
                rsa = re.search( """p=([\w\/\+]+)\\b""", str_txt ).group(1)
                key_len = get_key_length( rsa )
                print( "[+] Key length for %s is %d bits" % ( args.domain, key_len ) )
    except:
        print( "[!] Unable to parse TXT records" )


main()
