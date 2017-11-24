#!/usr/bin/env python3

"""
dkim_key_length_check.py: Pull DKIM records from DNS and validate the RSA key length.

Can either accept the Domain and Selector records directly, or it can pull them from an Outlook .msg file.

Requirements:
pyOpenSSL
olefile

History:
1.1.1 - externalised the printer module
"""
__author__ = "b4dpxl"
__credits__ = [ "https://protodave.com/" ]
__license__ = "GPL"
__version__ = "1.1.1"


import dns.resolver
import re
import argparse
from OpenSSL import crypto
import olefile
import os
import sys
from __printer import printer


def extract_headers( file ):
    if not os.path.exists( file ):
        printer().error( "File not found: %s" % file )
        sys.exit( -2 )
    try:
        ole = olefile.OleFileIO( file )
        header = str( ole.openstream('__substg1.0_007D001F').getvalue(), 'utf_16_le' )
    except:
        printer().error("Unable to parse .msg file")
        sys.exit(-3)
    if "DKIM-Signature" in header:
        print( "Got header" )
        s = re.search( """\\bs=([\\w\\-]+);""", header ).group(1)
        d = re.search( """\\bd=(([\\w+\\-]+\\.)+[\\w+\\-]+\\w+);""", header ).group(1)
        return (s, d)
    else:
        printer().info( "No DKIM Signature present" )
        sys.exit(-4)


def get_key_length( _key ):
    pub_key = crypto.load_publickey( crypto.FILETYPE_PEM, ( "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----" % _key ).encode() )
    return pub_key.bits()

def main():

    parser = argparse.ArgumentParser( description="""DKIM Key Length Checker

Checks for a valid DKIM record, then validates the length of the RSA key.
Either a Domain and Selector, or a File (Outlook .msg file) must be provided.
""", formatter_class=argparse.RawTextHelpFormatter )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument( '--domain', '-d', help='Enter the Domain name to verify. E.g. example.com' )
    parser.add_argument('--selector', '-s', help='Enter the Selector to verify [default]', required=False, default="default" )
    group.add_argument( '--file', '-f', help='Outlook message file (.msg) to analyse' )
    args = parser.parse_args()

    if args.file:
        selector, domain = extract_headers( args.file )
    else:
        selector = args.selector
        domain = args.domain

    domain_key = "%s._domainkey.%s" % ( selector, domain )

    printer().info( "Checking DKIM entry for %s" % domain_key )

    txt_list = []
    try:
        for txt in dns.resolver.query( domain_key, 'TXT').response.answer:
            txt_list.append( txt )
    except:
        printer().error( "No TXT records exist for %s" % domain_key )
        sys.exit(-1)

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
