#! /bin/env python3

"""
DNS server which redirects specified domains to another IP.
"""

from dnslib import DNSRecord, DNSHeader, A, RR
import argparse
import datetime
import os
import socket
import socketserver
import sys
import time
import threading
import traceback

try:
    from __printer import Printer
except:
    print("ERROR: Please download __printer.py from https://raw.githubusercontent.com/b4dpxl/tools/master/__printer.py")
    sys.exit(1)

class UDPRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):

        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        try:
            data = self.request[0].strip()
            request = DNSRecord.parse(data)
            qname = str(request.q.qname)
            domain = qname[:-1]

            if "*" in self.args.domain or domain in self.args.domain:
                ip = self.args.ip
            else:
                ip = socket.gethostbyname(domain)

            # ip = args.ip

            Printer().ok("{:<22}{:<18}{}".format(now, ip, domain))

            reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q, a=RR(qname, rdata=A(ip)))
            self.request[1].sendto(reply.pack(), self.client_address)

        except Exception as e:
            Printer().error("{}".format(e))

            reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q, a=RR(qname, rdata=A(socket.gethostbyname(domain))))
            self.request[1].sendto(reply.pack(), self.client_address)


class DNSListener:
    args = None

    def __init__(self, args):
        self.args = args

    def run(self):
        server = None
        try:

            Printer().info("Starting listener...")

            class MyUDPRequestHandler(UDPRequestHandler):
                args = self.args

            server = socketserver.ThreadingUDPServer(('', 53), MyUDPRequestHandler)
            thread = threading.Thread(target=server.serve_forever)  # that thread will start one more thread for each request
            thread.daemon = True  # exit the server thread when the main thread terminates
            thread.start()

            Printer().ok("Ready")
            Printer().info("Time                  IP Address        Domain")

            while 1:
                time.sleep(1)

        except KeyboardInterrupt:
            Printer().warn("Shutting down")

        except Exception as e:
            traceback.print_exc()

        finally:
            if server is not None:
                server.shutdown()


def main():
    parser = argparse.ArgumentParser(
                                    description="""DNS server which redirects specified domains to another IP.""", 
                                    formatter_class=argparse.RawTextHelpFormatter
        )
    parser.add_argument(
                        '-d', 
                        '--domain', 
                        dest='domain', 
                        help="Domain names to redirect. Use multiple times, or '*' (in quotes) for all domains.", 
                        action='append', 
                        required=True
                    )
    parser.add_argument('-i', '--ip', dest='ip', help="IP to redirect to", required=True)
    args = parser.parse_args()

    listener = DNSListener(args)

    try:
        listener.run()
    except Exception as e:
        Printer().error("{}".format(e))


main()
