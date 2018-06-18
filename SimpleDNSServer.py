#! /bin/env python

import argparse
import SocketServer
import sys
import time
import threading
import traceback
from dnslib import *


parser = argparse.ArgumentParser(description="Simple DNS Server, returns the specified IP address for all requests")
parser.add_argument("--ip", dest="ip", help="IP address to return", required=True)
args = parser.parse_args()

colours = {'purple':'\033[95m', 'green':'\033[92m', 'blue':'\033[94m', 'clear':'\033[0m'}

class UDPRequestHandler(SocketServer.BaseRequestHandler):
  def handle(self):

    try:
      data = self.request[0].strip()
      request = DNSRecord.parse(data)
      qname = str(request.q.qname)
      print("{0[purple]}[+]{0[clear]} {0[green]}{1}{0[clear]} requested {0[green]}{2}{0[clear]}".format(colours, self.client_address[0], qname))

      reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q, a=RR(qname, rdata=A(args.ip)))
      self.request[1].sendto(reply.pack(), self.client_address)

    except Exception:
      traceback.print_exc(file=sys.stderr)


def main():
  print("{0[blue]}[*]{0[clear]} Starting nameserver...".format(colours))

  servers = [
    SocketServer.ThreadingUDPServer(('', 53), UDPRequestHandler)
  ]

  for s in servers:
    thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
    thread.daemon = True  # exit the server thread when the main thread terminates
    thread.start()

  try:
    while 1:
      time.sleep(1)
      sys.stderr.flush()
      sys.stdout.flush()

  except KeyboardInterrupt:
    pass
  finally:
    for s in servers:
      s.shutdown()


main()