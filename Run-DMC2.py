#!/usr/bin/env python3

"""
Run-DMC2.py: Pull DKIM records from DNS and validate the RSA key length.

Can either accept the Domain and Selector records directly, or it can pull them from an Outlook .msg file.

Requirements:
pip3 install pyOpenSSL olefile dnspython

History:
0.1
0.2 - made into a Class
0.3 - added support for specifying name server to use
0.3.1 - updated DMARC text
"""
__author__ = "b4dpxl"
__credits__ = ["https://protodave.com/", "https://github.com/ins1gn1a/"]
__license__ = "GPL"
__version__ = "0.3.1"

import argparse
import dns.resolver
import re
import olefile
import os
import sys
from OpenSSL import crypto
from xml.etree import ElementTree as ET


class Printer:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    __debug_on = True
    __wrap_length = 0

    def __init__(self, debug=True, wrap=0):
        self.__debug_on = debug
        self.__wrap_length = wrap

    def ok(self, str):
        self.print_col("[+]", self.__wrap(str), self.OKGREEN)

    def info(self, str):
        self.print_col("[*]", self.__wrap(str), self.OKBLUE)

    def warn(self, str):
        self.print_col("[~]", self.__wrap(str), self.WARNING)

    def error(self, str):
        self.print_col("[!]", self.__wrap(str), self.FAIL)

    def debug(self, str):
        if self.__debug_on:
            self.__default("[-] %s" % self.__wrap(str))

    def print_col(self, str1, str2, col):
        print("%s%s%s %s" % (col, str1, self.ENDC, str2))

    def __default(self, str):
        print(str)

    def __wrap(self, str):
        if self.__wrap_length == 0:
            return str
        out = []
        wl = self.__wrap_length - 4 # "4" because of the "[x] "
        for line in str.split('\n'):
            tmp = line.strip()
            while len(tmp) > wl:
                # Try for a space to split on first so we don't mess up IP addresses and domains
                r = re.search(r"[\s]", tmp[wl - 1:])
                if r is not None:
                    i = r.start() + wl
                    out.append(tmp[:i].strip())
                    tmp = tmp[i:].strip()
                else:
                    if len(tmp) > wl + 15: # bit of a buffer to try and stop splitting the last word
                        # just hard split :(
                        out.append(tmp[:wl].strip())
                        tmp = tmp[wl:].strip()
                    else:
                        break
            out.append(tmp)
        # 4 spaces to accommodate "[x] "
        return "\n    ".join(out)


class EmailAnalyser:
    src_vulnerabilities = {
        "no-dmarc": { "id": "SC-2166", "text": "No DMARC records were present for the domain '%s'" },
        "no-spf": { "id": "SC-2090", "text": "No SPF records were present for the domain '%s'" },
        "no-dkim": { "id": "SC-2165", "text": "DKIM records were not present on the domain '%s', or no sample email was available to identify the DKIM Selector" },
# TODO we need a vuln for Weak DMARC
        "weak-dmarc": { "id": "", "text": "The domain '%s' was found to have the following issues with the DMARC records:\n- %s" },
        "weak-spf": { "id": "SC-2183", "text": "The domain '%s' was not found to have a secure SPF record configured, and as such it would be possible to spoof emails from the organisation (e.g. user.name@%s). The SPF record was set as the following:\n%s" },
        "weak-dkim": { "id": "SC-2187", "text": "The domain '%s' utilised a DKIM key, but the key length of %s was less than 2048-bits." },
        "overall": { "id": "SC-2157", "text": "An assessment of the standard email spoofing and SPAM prevention records on the '%s' domain was performed.\n\n%s" }
    }

    commentaries = []
    vulns = []

    domain = None
    dkim_domain = None
    selector = None
    name_server = None

    printer = None

    def __init__(self, file=None, domain=None, selector=None, quiet=False, wrap=0, ns=None):
        self.printer = Printer(debug=not quiet, wrap=wrap)
        if file is not None:
            self.selector, self.dkim_domain, self.domain = self.__extract_mail_headers(file)
        else:
            self.dkim_domain = self.domain = domain
            self.selector = selector
        self.name_server = ns
        if self.name_server is not None:
            self.printer.info("Using Name Server %s" % self.name_server)

    def __add_commentary(self, commentary):
        self.commentaries.append(commentary)

    def __add_vuln(self, vuln, options):
        self.vulns.append({ "id": vuln["id"], "text": vuln["text"] % options })

    def __extract_sender_domain_from_header(self, header):
        email_rex = r"(?<=@)(([\w\-]+\.)+[\w\-]+)"
        tags = [ "X-SENDER-ID:", "RETURN-PATH:", "FROM:" ]
        for tag in tags:
            if tag in header.upper():
                line = re.search(r"%s.*" % tag, header, re.IGNORECASE).group(0)
                res = re.search(email_rex, line)
                if res:
                    return(res.group(0))
        return None

    def __extract_mail_headers(self, file):
        selector = dkim_domain = None

        if not os.path.exists(file):
            self.printer.error("File not found: %s" % file)
            sys.exit(-2)
        try:
            ole = olefile.OleFileIO(file)
            header = str(ole.openstream('__substg1.0_007D001F').getvalue(), 'utf_16_le')
        except Exception as e:
            self.printer.error("Unable to parse .msg file: %s" % e)
            sys.exit(-3)
        if "DKIM-SIGNATURE" in header.upper():
            self.printer.info("DKIM Signature found in email")
            selector = re.search(r"\bs=([\w\-]+);", header).group(1)
            dkim_domain = re.search(r"\bd=(([\w+\-]+\.)+[\w+\-]+\w+);", header).group(1)
        else:
            self.printer.debug("No DKIM Signature present, inferring domain from sender")

        domain = self.__extract_sender_domain_from_header(header)
        if domain is not None:
            self.printer.debug("Found domain: '%s'" % domain)
            if dkim_domain is None:
                dkim_domain = domain
            return(selector, dkim_domain, domain)
        else:
            Printer.error("Unable to determine domain")
            sys.exit(-4)

    def __get_key_length(self, key):
        pub_key = crypto.load_publickey(crypto.FILETYPE_PEM, ("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----" % key).encode())
        return pub_key.bits()

    def __get_txt_records(self, domain):
        txt_list = []
        try:
            resolver = dns.resolver.Resolver()
            if self.name_server is not None:
                resolver.nameservers = [ self.name_server ]
            for txt in resolver.query(domain, 'TXT').response.answer:
                txt_list.append(txt)
        except:
            pass
        return txt_list

    def check_dkim(self):
        got_dkim = False

        if self.selector is not None:
            domain_key = "%s._domainkey.%s" % (self.selector, self.dkim_domain)
            self.printer.debug("Checking DKIM entry for %s" % domain_key)
            txt_list = self.__get_txt_records(domain_key)

            if len(txt_list) > 0:

                try:
                    for txt in txt_list:
                        str_txt = txt.to_text()
                        # handle long records - TXT records are max 255 chars, split into multiple parts after that
                        if len(str_txt) > 257:
                            str_txt = re.sub(r"\"\s+\"", "", str_txt)
                        if "k=rsa" in str_txt and "p=" in str_txt:
                            got_dkim = True
                            rsa = re.search("p=([\w\/\+]+)\\b", str_txt).group(1)
                            self.printer.debug("Found RSA key: %s" % rsa)
                            key_len = self.__get_key_length(rsa)
                            if key_len < 2048:
                                self.printer.warn("The DKIM RSA key length for %s is %d-bits" % (self.dkim_domain, key_len))
                                self.__add_vuln(self.src_vulnerabilities["weak-dkim"], (self.dkim_domain, key_len))
                                self.__add_commentary("\nThe domain '%s' utilised DKIM records, although the RSA key length was %s-bits, which is less than the current recomendation of 2048-bits." % (self.dkim_domain, key_len))
                            else:
                                self.printer.ok("The DKIM RSA key length for '%s' is %d-bits" % (self.dkim_domain, key_len))
                                self.__add_commentary("\nThe domain '%s' utilised DKIM records, with a key length of at least 2048-bits." % self.dkim_domain)

                except:
                    self.printer.error("Unable to parse TXT records")

        if not got_dkim:
            self.printer.error("No valid DKIM records present for %s" % self.dkim_domain)
            self.__add_vuln(self.src_vulnerabilities["no-dkim"], (self.dkim_domain))
            self.__add_commentary("\nThe domain '%s' did not appear to utilise DKIM records, or there was no sample email available to review from which to determine the DKIM domain selector." % self.dkim_domain)

    def check_spf(self,):
        txt_list = self.__get_txt_records(self.domain)
        got_spf = False

        if len(txt_list) > 0:
            try:
                for txt in txt_list:
                    str_txt = txt.to_text()
                    # handle long records - TXT records are max 255 chars, split into multiple parts after that
                    if len(str_txt) > 257:
                        str_txt = re.sub(r"\"\s+\"", "", str_txt)

                    if "v=spf" in str_txt.lower():
                        got_spf = self.__parse_spf(self.domain, re.search(r"v=spf[^\"]+", str_txt).group(0))

            except:
                self.printer.error("Unable to parse TXT records (DMARC)")

        if not got_spf:
            self.printer.error("No valid SPF records present for %s" % self.domain)
            self.__add_vuln(self.src_vulnerabilities["no-spf"], (self.domain))
            self.__add_commentary("No SPF records were identified for the domain '%s'." % self.domain)

    def __parse_spf(self, domain, record):
        self.printer.debug("Checking SPF record: %s" % record)
        allowed_servers = []
        try:
            self.printer.info("An SPF record is present for '%s'" % self.domain)
            params = ["include", "ip4", "ip6", "a", "ptr"]
            for param, value in [(x.strip(), y.strip()) for x, y in [x.split(":") for x in record.strip().split(" ") if ":" in x]]:
                if param in params:
                    allowed_servers.append(value)
                elif param == "mx":
                    allowed_servers.append("Mail Exchange (MX) servers")

            got_reject = False
            for param in [x for x in record.strip().split(" ") if ":" not in x ]:
                if param == "mx":
                    allowed_servers.append("Mail Exchange (MX) servers")
                elif param == "-all":
                    self.printer.ok("Only the following mail servers are authorised to send mail from the '%s' domain, with a hard fail for unauthorised servers:\n\t%s" % (domain, "\n\t".join(allowed_servers)))
                    self.__add_commentary("The domain '%s' utilised strong SPF records, with a hard fail for unauthorised servers. This configuration permits only servers operated by or on behalf of the organisation to send email. The permitted servers were: \n- %s" % (domain, "\n- ".join(allowed_servers)))
                    got_reject = True
                elif param == "~all":
                    self.printer.warn("The following mail servers are authorised to send mail from the '%s' domain, with a soft-fail for unauthorised servers: \n\t%s" % (domain, "\n\t".join(allowed_servers)))
                    self.__add_commentary("The domain '%s' utilised SPF records, although with a soft fail (~all) for unauthorised servers. This configuration permits only servers operated by or on behalf of the organisation to send email. However a soft fail should only be used as a transition to a hard fail (-all). The permitted servers were:\n- %s" % (domain, "\n- ".join(allowed_servers)))
                    got_reject = True

            if not got_reject:
                self.printer.error("The %s domain is configured in a way that would allow domain email spoofing to be performed." % domain)
                self.__add_commentary("The domain '%s' was not found to have a secure SPF record configured, and as such it would be possible to spoof emails from the organisation (e.g. user.name@%s). The SPF record was set as:\n- %s" % (domain, domain, record))
                self.__add_vuln(self.src_vulnerabilities["weak-spf"], (domain, domain, record))

            return True

        except:
            return False

    def check_dmarc(self):
        txt_list = self.__get_txt_records("_dmarc.%s" % self.domain)
        got_dmarc = False
        if len(txt_list) > 0:
            try:
                for txt in txt_list:
                    str_txt = txt.to_text()
                    # handle long records - TXT records are max 255 chars, split into multiple parts after that
                    if len(str_txt) > 257:
                        str_txt = re.sub(r"\"\s+\"", "", str_txt)

                    if "v=DMARC" in str_txt:
                        # self.printer.comment("Found DMARC: %s" % str_txt)
                        got_dmarc = self.__parse_dmarc(self.domain, re.search(r"v=DMARC[^\"]+", str_txt).group(0))

            except:
                self.printer.error("Unable to parse TXT records (DMARC)")

        if not got_dmarc:
            self.printer.error("No DMARC records are present for %s" % self.domain)
            self.__add_vuln(self.src_vulnerabilities["no-dmarc"], (self.domain))
            self.__add_commentary("\n\nThere were no DMARC records found within the Domain Name (DNS) TXT entries for '_dmarc.%s'. Implementing DMARC alongside SPF would provide granular control for the management and monitoring of email spoofing, and allow the organisation to proactively respond to possible abuse." % self.domain)

    def __parse_dmarc(self, domain, record):
        self.printer.debug("Checking DMARC record: %s" % record)
        dmarc_vulns = []
        try:
            self.printer.info("A DMARC record is present for '%s'" % self.domain)
            self.__add_commentary("\nThe DMARC configuration for '%s' was configured such that:" % domain)
            report_addresses = []
            for param,value in [ (x.strip(), y.strip()) for x,y in [ x.split("=") for x in record.lower().split(";") if len(x) > 0 ] ]:
# TODO Check for SPF/DMARC non-authorised rejection (No mail)
                if param == "p":
                    if value == "quarantine":
                        self.printer.info("p=quarantine: Suspicious emails should be marked as suspected SPAM.")
                        self.__add_commentary("- suspicious emails should be marked as SPAM.")
                    elif value == "reject":
                        self.printer.ok("p=reject: Emails that fail DKIM or SPF checks should be rejected.")
                        self.__add_commentary("- emails failing DKIM or SPF checked should be rejected.")
                    elif value == "none":
                        self.printer.warn("p=none: No specific actions are recommended to be performed against emails that have failed DMARC checks.")
                        self.__add_commentary("- no specific actions are recommended to be performed against emails that have failed DMARC checks, and so these emails may not be identified as invalid.")
                        dmarc_vulns.append("No specific actions are recommended to be performed against emails that have failed DMARC checks, and so these emails may not be identified as invalid.")
                    else:
                        self.printer.error("%s=%s: Unknown option" % (param, value))

                elif param == "adkim":
                    if value == "r":
                        self.printer.info("adkim=r (Relaxed Mode): Emails from *.%s are permitted." % domain)
                        self.__add_commentary("- all emails from subdomains of '%s' would be permitted." % domain)
                    elif value == "s":
                        self.printer.ok("adkim=s (Strict Mode): Sender domains must match DKIM mail headers exactly. E.g. if 'd=%s' then emails are not permitted from subdomains." % domain)
                        self.__add_commentary("- only emails from domains exactly matching '%s' would be permitted." % domain)
                    else:
                        self.printer.error("%s=%s: Unknown option" % (param, value))

                elif param == "pct":
                    self.printer.info("pct=%s: %s%% of received mail is subject to DMARC processing." % (value, value))
                    self.__add_commentary("- %s%% of emails received would be subject to DMARC processing." % value)

                elif param == "aspf":
                    if value == "r":
                        self.printer.warn("aspf=r (Relaxed Mode): Any sub-domains from '%s' are permitted to match DMARC to SPF records." % domain)
                        dmarc_vulns.append("Any sub-domains from '%s' are permitted to match DMARC to SPF records." % domain)
                    elif value == "s":
                        self.printer.info("aspf=s (Strict Mode): The 'header from' domain and SPF must match exactly to pass DMARC checks.")
                    else:
                        self.printer.error("%s=%s: Unknown option." % (param, value))

                elif param == "rua":
                    for address in [ x.strip() for x in value.split(",") ]:
                        if address[0:7] != "mailto:":
                            self.printer.error("rua=: Aggregate mail reports will not be sent as incorrect syntax is used. Prepend 'mailto:' before mail addresses. '%s'" % address)
                            self.__add_commentary("- invalid email addresses (i.e. without the prepended 'mailto:') were included in the SPF configuration: '%s'" % address)
                            dmarc_vulns.append("Invalid email addresses (i.e. without the prepended 'mailto:') were included in the SPF configuration: '%s'" % address)
                        else:
                            report_addresses.append(address[8:].strip())
                    if len(report_addresses) > 0:
                        self.printer.ok("rua=: Aggregate mail reports will be sent to the following email addresses:\n\t%s" % ("\n\t".join(report_addresses)))

            if len(report_addresses) > 0:
                self.__add_commentary("\nDMARC email aggregation reports for '%s' were configured to be sent to:\n- %s" % (domain, "\n- ".join(report_addresses)))

# TODO If we get a weak-dmarc vuln, we can enable this next bit
#            if len(dmarc_vulns) > 0:
#                self.__add_vuln(self.src_vulnerabilities["weak-dmarc"], (self.domain, "\n- ".join(dmarc_vulns)))

            return True
        except:
            return False


    def generate_sureformat_xml(self, path):
        commentary = self.src_vulnerabilities["overall"]
        commentary["text"] = commentary["text"] % (self.domain, ("\n".join(self.commentaries).strip()))
        xroot = ET.Element("items", {
            "source": "SureFormat",
            "version": "1.2"
        })
        xitem = ET.SubElement(xroot, "item", {
            "hostname": self.domain,
            "ipaddress": ""
        })
        xservices = ET.SubElement(xitem, "services")
        xservice = ET.SubElement(xservices, "service", {
            "name": "",
            "port": "",
            "protocol": "tcp"
        })
        xvulnerabilities = ET.SubElement(xservice, "vulnerabilities")
        xvulnerability = ET.SubElement(xvulnerabilities, "vulnerability", {"id": commentary["id"]})
        xinformation = ET.SubElement(xvulnerability, "information")
        xinformation.text = commentary["text"]

        for id,text in [ (x["id"],x["text"]) for x in self.vulns ]:
            xvulnerability = ET.SubElement(xvulnerabilities, "vulnerability", {"id": id})
            xinformation = ET.SubElement(xvulnerability, "information")
            xinformation.text = text
        if path.strip() == '-':
            print(ET.tostring(xroot).decode())
        else:
            ET.ElementTree(xroot).write(path, encoding='utf-8', xml_declaration=True)


def main():

    parser = argparse.ArgumentParser(description="""SPF & DMARC record validator, and DKIM key length checker

Checks for and validates SPF and DMARC DNS records. 
Checks for a valid DKIM record, then validates the length of the RSA key.
Either a Domain and optional Selector, or a File (Outlook .msg file) must be provided.
""", formatter_class=argparse.RawTextHelpFormatter)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--domain', '-d', help="Enter the Domain name to verify. E.g. example.com")
    parser.add_argument('--selector', '-s', help="Enter the Selector to verify [default='default']", required=False, default="default")
    group.add_argument('--file', '-f', help="Outlook message file (.msg) to analyse")
    parser.add_argument('--output', '-o', help="SureFormat output file. Use '-' for stdout", required=False)
    parser.add_argument('--no-dkim', dest="no_dkim", help="Skip DKIM checks", required=False, action="store_true")
    parser.add_argument('--quiet', '-q', help="Exclude info messages", required=False, action="store_true")
    parser.add_argument('--wrap', '-w', help="Wrap output at ~80 characters", required=False, action="store_true")
    parser.add_argument('--ns', dest="name_server", help="Name server to use instead of network default", required=False, default=None)
    args = parser.parse_args()

    wrap_length = 0 if not args.wrap else 80

    if args.file:
        #selector, dkim_domain, domain = extract_mail_headers(args.file)
        analyser = EmailAnalyser(file=args.file, quiet=args.quiet, wrap=wrap_length, ns=args.name_server)
    else:
        # selector = args.selector
        # dkim_domain = domain = args.domain
        analyser = EmailAnalyser(domain=args.domain, selector=args.selector, quiet=args.quiet, wrap=wrap_length, ns=args.name_server)

    analyser.check_spf()
    analyser.check_dmarc()
    if not args.no_dkim:
        analyser.check_dkim()

    if args.output:
        analyser.generate_sureformat_xml(args.output)


main()
