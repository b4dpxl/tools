#! /bin/env python3

"""
pyDNSExfiltrateD.py: Act as a DNS listener, and record the lookups to a log file with timestamp & source nameserver IP.


Example:
> dig this.is.a.test.dns.my.domain.com
2016-10-18 18:56:57   127.0.0.1          this is a test

Requirements:
python-daemon
dnslib

History:
0.1 - this version
0.2 - Updated to python 3 and added non-daemon (foreground) mode
"""
__author__ = "b4dpxl"
__license__ = "GPL"
__version__ = "0.2"


# TODO update to python3 and Printer

from dnslib import DNSRecord, DNSHeader, A, RR
import daemon
from daemon import pidfile
import argparse
import datetime
import os
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

def write(text, file):
    if file is not None:
        with open(file, 'a') as f:
            f.write(text)


class UDPRequestHandler(socketserver.BaseRequestHandler):

    args = None
    outfile = None

    def handle(self):

        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        try:
            data = self.request[0].strip()
            request = DNSRecord.parse(data)
            qname = str(request.q.qname)
            text = qname[:-(len(self.args.domain)+2)].replace('.', ' ')
            write("{:<22}{:<18}{}\n".format(now, self.client_address[0], text), self.args.out)

            if self.args.foreground:
                Printer().ok("{:<22}{:<18}{}".format(now, self.client_address[0], text))

            reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q, a=RR(qname, rdata=A("127.0.0.1")))
            self.request[1].sendto(reply.pack(), self.client_address)

        except Exception as e:
            if self.args.foreground:
                Printer().error("{}".format(e))
            write("ERROR3: {}\n".format(e), self.args.out)


class DNSListener:

    args = None

    def __init__(self, args):
        self.args = args

    def run(self):
        server = None
        try:

            now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
            write("Starting at {}\n".format(now), self.args.out)

            if self.args.foreground:
                Printer().info("Starting listener...")
                Printer().info("Recording to {}".format(self.args.out))

            class MyUDPRequestHandler(UDPRequestHandler):
                args = self.args

            server = socketserver.ThreadingUDPServer(('', 53), MyUDPRequestHandler)
            thread = threading.Thread(target=server.serve_forever)  # that thread will start one more thread for each request
            thread.daemon = True  # exit the server thread when the main thread terminates
            thread.start()

            if self.args.foreground:
                Printer().ok("Ready")
                Printer().info("{:<22}{:<18}Message".format("Time", "IP Address"))

            while 1:
                time.sleep(1)

        except KeyboardInterrupt:
            if self.args.foreground:
                Printer().warn("Shutting down")

        except Exception as e:
            traceback.print_exc()
            write("ERROR2: {}\n".format(sys.exc_info()), self.args.out)

        finally:
            if server is not None:
                server.shutdown()


def main():

    parser = argparse.ArgumentParser(description="""DNS exfiltrator""", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-f', action='store_true', dest="foreground", help="Run in the foreground, not as a daemon", required=False, default=False)
    parser.add_argument('-o', '--out', dest='out', help="Output file", default=None)
    parser.add_argument('--pid', dest='pid', help="PID file, defaults to '/var/run/pyDNS.pid'", default="/var/run/pyDNS.pid")
    parser.add_argument('-d', '--domain', dest='domain', help="Your domain name", required=True)
    parser.add_argument('--version', '-v', action='version', version='%(prog)s {}'.format(__version__))
    args = parser.parse_args()

    listener = DNSListener(args)

    if args.foreground:
        try:
            listener.run()
        except Exception as e:
            Printer().error("{}".format(e))

    else:
        context = None
        try:
            if os.path.exists(args.pid):
                Printer().error("PID file '{}' exists and/or process already running. Did you 'kill -9'?".format(args.pid))
                sys.exit(1)

            context = daemon.DaemonContext(
                pidfile=pidfile.PIDLockFile(args.pid)
                # , stdout=open("/tmp/dns.out", 'w')
                # , stderr=open("/tmp/dns.err", 'w')
            )
            context.open()
            listener.run()

        except Exception as e:
            write("ERROR1: {}\n".format(e), args.out)

        finally:
            try:
                if context is not None:
                    context.close()
            except:
               pass


main()

