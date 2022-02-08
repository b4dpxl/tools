#! /usr/bin/env python3

"""
Simple script to start a SSl/TLS listener with your choice of protocol. Useful for testing protocol version support.

The protocol versions supported are reliant on the version of OpenSSL available on the host.

To generate a certificate: 
    openssl req -new -x509 -keyout tls_cert.pem -out tls_cert.pem -days 365 -nodes
"""

import argparse
import os
import ssl
import sys

from http.server import BaseHTTPRequestHandler, HTTPServer

parser = argparse.ArgumentParser(description="Basic HTTPS listener with choice of SSL/TLS version")
parser.add_argument('-p', '--port', dest='port', help="Port", type=int, required=True)
parser.add_argument('--host', dest='host', help="Host to bind to [0.0.0.0]", default='0.0.0.0')
parser.add_argument('--cert', dest='cert', default=os.path.dirname(os.path.abspath(__file__)) + '/tls_cert.pem', help="certificate file to use [./tls_cert.pem]")

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--ssl2', dest='ssl2', help="Use SSLv2", action='store_true')
group.add_argument('--ssl3', dest='ssl3', help="Use SSLv3", action='store_true')
group.add_argument('--tls10', dest='tls10', help="Use TLS1.0", action='store_true')
group.add_argument('--tls11', dest='tls11', help="Use TLS1.1", action='store_true')
group.add_argument('--tls12', dest='tls12', help="Use TLS1.2", action='store_true')

args = parser.parse_args()

if not os.path.exists(args.cert):
    print("[!] Invalid certificate file: {}".format(args.cert))
    sys.exit(-1)

tls_protocol_name = (
    "SSLv2" if args.ssl2
    else "SSLv3" if args.ssl3
    else "TLSv1" if args.tls10
    else "TLSv1.1" if args.tls11
    else "TLSv1.2" if args.tls12
    else None
)
tls_protocol = (
    ssl.PROTOCOL_SSLv2 if args.ssl2 
    else ssl.PROTOCOL_SSLv3 if args.ssl3 
    else ssl.PROTOCOL_TLSv1 if args.tls10 
    else ssl.PROTOCOL_TLSv1_1 if args.tls11 
    else ssl.PROTOCOL_TLSv1_2 if args.tls12 
    else None
)

print("[*] Using {}".format(tls_protocol_name))

if tls_protocol is None:
    raise ArgumentException("Invalid Protocol")

class MyRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(bytes(tls_protocol_name + "\n", "utf8"))

    def do_POST(self):
        self.do_GET()


ctx = ssl.SSLContext(protocol=tls_protocol )
ctx.load_cert_chain(args.cert)

httpd = HTTPServer((args.host, args.port), MyRequestHandler)
httpd.socket = ctx.wrap_socket(
    httpd.socket, 
    server_side=True
)
httpd.serve_forever()


