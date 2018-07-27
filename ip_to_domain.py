#! /usr/bin/env python3

"""
ip_to_domain.py: Attempt to determine host name for a given IP address. Can perform Reverse DNS lookup and attempt to extract Subject from any SSL/TLS certificate.

Accepts one of:
- ip and port
- file containing records in the format "ip:port", one per line
- NMAP XML file

For the first two options, certificate checking can be prevented by passing the parameter --no-ssl. For NMAP files, HTTP/HTTPS is taken from the XML file and used accordingly.

Requirements:
pyOpenSSL
dnspython

History:
0.4 - added support for different SSL/TLS versions
0.5 - externalised the printer module
0.6 - Updated to ".format", just because I can

"""
__author__ = "b4dpxl"
__license__ = "GPL"
__version__ = "0.6"

import sys
import argparse
import socket
from OpenSSL import SSL
import dns.reversename, dns.resolver
import os
import xml.etree.ElementTree as etree
try:
    from __printer import Printer
except:
    print("ERROR: Please download __printer.py from https://raw.githubusercontent.com/b4dpxl/tools/master/__printer.py")
    sys.exit(1)


def __get_cert(client, ip, ssl_method):
    Printer().debug("Attempting connection with SSL/TLS method {}".format(ssl_method))
    client_ssl = SSL.Connection(SSL.Context(ssl_method), client)
    try:
        client_ssl.set_connect_state()
        client_ssl.set_tlsext_host_name(ip.encode())
        client_ssl.do_handshake()
        return (client_ssl.get_peer_certificate(), 0, None)
    except SSL.Error as e:
        # ssl/tls version error
        return (None, -2, e)
    except Exception as e:
        # Printer().error("Unable to establish secure connection to {}:{}".format(ip, port))
        return (None, -1, e)
    finally:
        client_ssl.close()


def __get_ssl_subject(ip, port):
    try:
        methods = [SSL.TLSv1_2_METHOD, SSL.TLSv1_1_METHOD, SSL.TLSv1_METHOD, SSL.SSLv3_METHOD]
        cert = None
        for method in methods:
            client = socket.socket()
            client.connect((ip, port))
            Printer().debug("Connected to {}".format(str(client.getpeername())))

            (cert, errno, err) = __get_cert(client, ip, method)
            if errno == 0:
                break
            client.close()

        if cert is not None:
            return cert.get_subject().CN
        elif errno == -2:
            Printer().error("Unable to establish secure SSL or TLS connection to {}:{}".format(ip, port))
        else:
            Printer().error("Unable to establish secure connection to {}:{}; Error msg: {}".format(ip, port, err))

    except Exception as e:
        Printer().error("Unable to connect to {}:{}; Error msg: {}".format(ip, port, e))
        return None

    finally:
        client.close()


def __get_reverse_dns(ip):
    try:
        rev = dns.reversename.from_address(ip)
        return str(dns.resolver.query(rev, "PTR")[0])
    except dns.resolver.NXDOMAIN as e:
        Printer().warn("No Reverse DNS entry")
    except Exception as e:
        #print(e)
        Printer().error("Unable to query DNS")


def __lookup(host, port, nossl=False, out=None):
    Printer().info("Checking {}:{}".format(host, port))
    proto = None
    if not nossl:
        CN = __get_ssl_subject(host, port)
        if CN != None:
            Printer().ok("Certificate Subject: {}".format(CN))
            # managed to get something from the certificate, must be HTTPS :)
            proto = "https"
            if CN.startswith("*."):
                Printer().warn("Wildcard certificate in use")
            elif out is not None:
                out.write("{}://{}:{}\n".format(proto, CN, port))

    PTR = __get_reverse_dns(host)
    if PTR is not None:
        if out is not None:
            if proto is None:
                # not worked out the protocol from the cert, or not checked the cert. Try and guess from the port
                proto = "http"
                ssl_ports = [443, 8443]
                if port in ssl_ports:
                    proto = "https"
            out.write("{}://{}:{}\n".format(proto, PTR[:-1], port))
        Printer().ok("Reverse DNS: {}".format(PTR[:-1]))


def __check_file(file):
    if not os.path.exists(file):
        Printer().error("File {} not found".format(file))
        sys.exit(-1)


def process_file(file, nossl=False, out=None):
    __check_file(file)
    with open(file, 'r') as f:
        for line in f.readlines():
            if ":" in line:
                (host, port) = line.strip().split(':')
                try:
                    socket.inet_aton(host)
                    p_int = int(port)
                except socket.error as e:
                    Printer().error("Invalid IP address '{}'".format(host))
                    continue
                except ValueError as e:
                    Printer().error("Invalid port '{}'".format(port))
                    continue
                __lookup(host, p_int, nossl, out)


"""
<nmaprun>
    <host starttime="1497890861" endtime="1497893068">
        <status state="up" reason="user-set" reason_ttl="0"/>
        <address addr="127.0.0.1" addrtype="ipv4"/>
        <ports>
            <port protocol="tcp" portid="80">
                <state state="closed" reason="reset" reason_ttl="244"/>
                <service name="http" method="table" conf="3"/>
            </port>
            <port protocol="tcp" portid="443">
                <state state="open" reason="syn-ack" reason_ttl="244"/>
                <service name="http" tunnel="ssl" method="probed" conf="10"/>
            </port>
            <port protocol="tcp" portid="443">
                <state state="open" reason="syn-ack" reason_ttl="117"/>
                <service name="https" method="table" conf="3"/>
            </port>
        </ports>
"""


def process_xml(file, nossl=False, out=None):
    __check_file(file)
    targets = []
    xml = etree.parse(file)
    root = xml.getroot()
    hosts = root.findall("host")
    for host in hosts:
        if host.find("status[@state='up']") is not None:
            ip = host.find("address[@addrtype='ipv4']").attrib["addr"]
            for port in host.findall("ports/port[@protocol='tcp']"):
                if port.find("state[@state='open']") is not None:
                    p = int(port.attrib["portid"])
                    if port.find("service[@name='http']") is not None:
                        no_ssl = port.find("service[@tunnel='ssl']") is None or nossl # http or --no-ssl set
                        __lookup(ip, p, no_ssl, out)

                    if port.find("service[@name='https']") is not None:
                        __lookup(ip, p, nossl, out=out)
    return


def main():

    parser = argparse.ArgumentParser(description="""Utility to obtain hostnames from IP's, using DNS records and TLS certificates
    
One of IP address (host), a file containing a list of records in the format ip:port, or an NMAP XML file must be provided.
""", formatter_class=argparse.RawTextHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--ip", dest="host", help="IP Address")
    group.add_argument("-f", "--file", help="File to parse, IP:PORT per line")
    group.add_argument("-x", "--xml", help="NMAP XML output file to parse")

    parser.add_argument("-o", "--output", help="Output file to write entries to in the form \"hostname:port\"")

    parser.add_argument("-p", "--port", help="Port, default 443", type=int, default=443)
    parser.add_argument("--no-ssl", dest="nossl", help="Don't attempt to query the TLS certificate (rDNS only). Only applies to host/port and file lookups", action="store_true")
    parser.add_argument('--version', '-v', action='version', version='%(prog)s {}'.format(__version__))
    args = parser.parse_args()

    out = None
    if args.output:
        out = open(args.output, 'w')
        if args.nossl and not args.xml:
            Printer().warn("Not performing Certificate lookup, protocols will be based on port")

    if args.file:
        process_file(args.file, args.nossl, out)

    elif args.xml:
        process_xml(args.xml, args.nossl, out)

    else:
        __lookup(args.host, args.port, args.nossl, out)

    if out is not None:
        out.close()


main()
