#!/usr/bin/env python3

"""
email_header_checker.py: Pull DKIM records from DNS and validate the RSA key length.

Can either accept the Domain and Selector records directly, or it can pull them from an Outlook .msg file.

Requirements:
pip3 install pyOpenSSL olefile dnspython

History:
0.1
0.2 - made into a Class
0.3 - added support for specifying name server to use
0.3.1 - updated DMARC text
0.4 - externalised Printer and updated to use ".format" because 'reasons'
0.5 - Added support for neutral all SPF records (?all)
0.5.1 - Fixed issues with '?all'reporting. DKIM reports now distinguish between no DKIM and no sample email
0.5.2 - Updated DKIM record check. "k=" is optional, MS seem to leave it off.
0.5.3 - Debranded
0.5.4 - Allowed override for --domain when specifying --file
"""
__author__ = "b4dpxl"
__credits__ = ["https://protodave.com/", "https://github.com/ins1gn1a/"]
__license__ = "GPL"
__version__ = "0.5.4"

import argparse
import dns.resolver
import re
import olefile
import os
import sys
from OpenSSL import crypto
from xml.etree import ElementTree as ET
try:
    from __printer import Printer
except:
    print("ERROR: Please download __printer.py from https://raw.githubusercontent.com/b4dpxl/tools/master/__printer.py")
    sys.exit(1)

class EmailAnalyser:
    src_vulnerabilities = {
        "no-dmarc": {"id": "1", "text": "No DMARC records were present for the domain '{domain}'"},
        "no-spf": {"id": "2", "text": "No SPF records were present for the domain '{domain}'"},
        "no-dkim": {"id": "SC-2165", "text": "DKIM records were not present on the domain '{dkim_domain}' which sent the sample email"},
        "no-dkim-file": {"id": "SC-2165", "text": "DKIM records were not present on the domain '{domain}', or no sample email was available to identify the DKIM Selector"},
        "weak-dmarc": {"id": "5", "text": "The domain '{domain}' was found to have the following issues with the DMARC records:\n- {issues}"},
        "weak-spf": {"id": "6", "text": "The domain '{domain}' was not found to have a secure SPF record configured, and as such it would be possible to spoof emails from the organisation (e.g. user.name@{domain}). The SPF record was set as the following:\n{spf}"},
        "weak-dkim": {"id": "7", "text": "The domain '{domain}' utilised a DKIM key, but the key length of {length} was less than 2048-bits."},
        "overall": {"id": "8", "text": "An assessment of the standard email spoofing and SPAM prevention records on the '{domain}' domain was performed.\n\n{text}"}
   }

    commentaries = []
    vulns = []

    domain = None
    dkim_domain = None
    selector = None
    name_server = None
    has_file = False

    printer = None

    def __init__(self, file=None, domain=None, selector=None, quiet=False, wrap=0, ns=None):
        self.printer = Printer(debug=not quiet, wrap=wrap)
        if file is not None:
            self.selector, self.dkim_domain, self.domain = self.__extract_mail_headers(file)
            if domain:
                self.domain = domain # use override domain
            self.has_file = True
        else:
            self.dkim_domain = self.domain = domain
            self.selector = selector
        self.name_server = ns
        if self.name_server is not None:
            self.printer.info("Using Name Server {}".format(self.name_server))

    def __add_commentary(self, commentary):
        self.commentaries.append(commentary)

    def __add_vuln(self, vuln, options={}):
        x = options
        x['domain'] = self.domain
        x['dkim_domain'] = self.dkim_domain
        self.vulns.append({"id": vuln["id"], "text": vuln["text"].format(**x)})

    def __extract_sender_domain_from_header(self, header):
        email_rex = r"(?<=@)(([\w\-]+\.)+[\w\-]+)"
        tags = [ "X-SENDER-ID:", "RETURN-PATH:", "FROM:" ]
        for tag in tags:
            if tag in header.upper():
                line = re.search(r"{}.*".format(tag), header, re.IGNORECASE).group(0)
                res = re.search(email_rex, line)
                if res:
                    return(res.group(0))
        return None

    def __extract_mail_headers(self, file):
        selector = dkim_domain = None

        if not os.path.exists(file):
            self.printer.error("File not found: '{}'".format(file))
            sys.exit(-2)
        try:
            ole = olefile.OleFileIO(file)
            header = str(ole.openstream('__substg1.0_007D001F').getvalue(), 'utf_16_le')
        except Exception as e:
            self.printer.error("Unable to parse .msg file: {}".format(e))
            sys.exit(-3)
        if "DKIM-SIGNATURE" in header.upper():
            self.printer.info("DKIM Signature found in email")
            selector = re.search(r"\bs=([\w\-]+);", header).group(1)
            dkim_domain = re.search(r"\bd=(([\w+\-]+\.)+[\w+\-]+\w+);", header).group(1)
        else:
            self.printer.debug("No DKIM Signature present, inferring domain from sender")

        domain = self.__extract_sender_domain_from_header(header)
        if domain is not None:
            self.printer.debug("Found domain: '{}'".format(domain))
            if dkim_domain is None:
                dkim_domain = domain
            return selector, dkim_domain, domain
        else:
            self.printer.error("Unable to determine domain")
            sys.exit(-4)

    def __get_key_length(self, key):
        pub_key = crypto.load_publickey(crypto.FILETYPE_PEM, ("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----".format(key)).encode())
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
            domain_key = "{}._domainkey.{}".format(self.selector, self.dkim_domain)
            self.printer.debug("Checking DKIM entry for {}".format(domain_key))
            txt_list = self.__get_txt_records(domain_key)

            if len(txt_list) > 0:

                try:
                    for txt in txt_list:
                        str_txt = txt.to_text()
                        # handle long records - TXT records are max 255 chars, split into multiple parts after that
                        if len(str_txt) > 257:
                            str_txt = re.sub(r"\"\s+\"", "", str_txt)
                        if "p=" in str_txt:
                            got_dkim = True
                            rsa = re.search("p=([\w\/\+]+)\\b", str_txt).group(1)
                            self.printer.debug("Found RSA key:\n    {}".format(rsa))
                            key_len = self.__get_key_length(rsa)
                            if key_len < 2048:
                                self.printer.warn("The DKIM RSA key length for {} is {:d}-bits".format(self.dkim_domain, key_len))
                                self.__add_vuln(self.src_vulnerabilities["weak-dkim"], {'length':key_len})
                                self.__add_commentary("\nThe domain '{}' utilised DKIM records, although the RSA key length was {:d}-bits, which is less than the current recomendation of 2048-bits.".format(self.dkim_domain, key_len))
                            else:
                                self.printer.ok("The DKIM RSA key length for '{}' is {:d}-bits".format(self.dkim_domain, key_len))
                                self.__add_commentary("\nThe domain '{}' utilised DKIM records, with a key length of at least 2048-bits.".format(self.dkim_domain))

                except:
                    self.printer.error("Unable to parse TXT records")

        if not got_dkim:
            self.printer.error("No valid DKIM records present for {}".format(self.dkim_domain))
            if self.has_file:
                self.__add_vuln(self.src_vulnerabilities["no-dkim"])
                self.__add_commentary("\nThe domain '{}' did not appear to utilise DKIM records.".format(self.dkim_domain))
            else:
                self.__add_vuln(self.src_vulnerabilities["no-dkim-file"])
                self.__add_commentary("\nThe domain '{}' did not appear to utilise DKIM records, or there was no sample email available to review from which to determine the DKIM domain selector.".format(self.dkim_domain))

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
            self.printer.error("No valid SPF records present for {}".format(self.domain))
            self.__add_vuln(self.src_vulnerabilities["no-spf"])
            self.__add_commentary("No SPF records were identified for the domain '{}'.".format(self.domain))

    def __parse_spf(self, domain, record):
        self.printer.debug("Checking SPF record:\n    {}".format(record))
        allowed_servers = []
        try:
            self.printer.info("An SPF record is present for '{}'".format(self.domain))
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
                    self.printer.ok("Only the following mail servers are authorised to send mail from the '{}' domain, with a hard fail for unauthorised servers:\n    {}".format(domain, "\n    ".join(allowed_servers)))
                    self.__add_commentary("The domain '{}' utilised strong SPF records, with a hard fail for unauthorised servers. This configuration permits only servers operated by or on behalf of the organisation to "
                                          "send email. The permitted servers were: \n- {}".format(domain, "\n- ".join(allowed_servers)))
                    got_reject = True
                elif param == "~all":
                    self.printer.warn("The following mail servers are authorised to send mail from the '{}' domain, with a soft-fail for unauthorised servers: \n    {}".format(domain, "\n    ".join(allowed_servers)))
                    self.__add_commentary("The domain '{}' utilised SPF records, although with a soft fail (~all) for unauthorised servers. This configuration permits only servers operated by or on behalf of the organisation "
                                          "to send email. However a soft fail should only be used as a transition to a hard fail (-all). The permitted servers were:\n- {}".format(domain, "\n- ".join(allowed_servers)))
                    got_reject = True
                elif param == "?all":
                    self.printer.error("The following mail servers are authorised to send mail from the '{}' domain, with a neutral 'all' record for unauthorised servers which would allow domain email spoofing to be "
                                       "performed: \n    {}".format(domain, "\n    ".join(allowed_servers)))
                    self.__add_commentary("The domain '{0}' utilised SPF records, although with a neutral 'all' record (?all) for unauthorised servers. This configuration permits any servers to send email and as such "
                                          "it would be possible to spoof emails from the organisation (e.g. user.name@{0}). The neutral 'all' record should be transitioned to a hard fail (-all). The permitted servers "
                                          "were:\n- {1}".format(domain, "\n- ".join(allowed_servers)))
                    self.__add_vuln(self.src_vulnerabilities["weak-spf"], {'spf': record})
                    got_reject = True

            if not got_reject:
                self.printer.error("The '{}' domain is configured in a way that would allow domain email spoofing to be performed.".format(domain))
                self.__add_commentary("The domain '{0}' was not found to have a secure SPF record configured, and as such it would be possible to spoof emails from the organisation (e.g. user.name@{0}). The SPF record "
                                      "was set as:\n- {1}".format(domain, record))
                self.__add_vuln(self.src_vulnerabilities["weak-spf"], {'spf':record})

            return True

        except:
            return False

    def check_dmarc(self):
        txt_list = self.__get_txt_records("_dmarc.{}".format(self.domain))
        got_dmarc = False
        if len(txt_list) > 0:
            try:
                for txt in txt_list:
                    str_txt = txt.to_text()
                    # handle long records - TXT records are max 255 chars, split into multiple parts after that
                    if len(str_txt) > 257:
                        str_txt = re.sub(r"\"\s+\"", "", str_txt)

                    if "v=DMARC" in str_txt:
                        # self.printer.comment("Found DMARC: {}".formatstr_txt))
                        got_dmarc = self.__parse_dmarc(self.domain, re.search(r"v=DMARC[^\"]+", str_txt).group(0))

            except:
                self.printer.error("Unable to parse TXT records (DMARC)")

        if not got_dmarc:
            self.printer.error("No DMARC records are present for '{}'".format(self.domain))
            self.__add_vuln(self.src_vulnerabilities["no-dmarc"])
            self.__add_commentary("\n\nThere were no DMARC records found within the Domain Name (DNS) TXT entries for '_dmarc.{}'. Implementing DMARC alongside SPF would provide granular control for the management and monitoring of email spoofing, and allow the organisation to proactively respond to possible abuse.".format(self.domain))

    def __parse_dmarc(self, domain, record):
        self.printer.debug("Checking DMARC record:\n    {}".format(record))
        dmarc_vulns = []
        try:
            self.printer.info("A DMARC record is present for '{}'".format(self.domain))
            self.__add_commentary("\nThe DMARC configuration for '{}' was configured such that:".format(domain))
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
                        self.printer.error("{}={}: Unknown option".format(param, value))

                elif param == "adkim":
                    if value == "r":
                        self.printer.info("adkim=r (Relaxed Mode): Emails from *.{} are permitted.".format(domain))
                        self.__add_commentary("- all emails from subdomains of '{}' would be permitted.".format(domain))
                    elif value == "s":
                        self.printer.ok("adkim=s (Strict Mode): Sender domains must match DKIM mail headers exactly. E.g. if 'd={}' then emails are not permitted from subdomains.".format(domain))
                        self.__add_commentary("- only emails from domains exactly matching '{}' would be permitted.".format(domain))
                    else:
                        self.printer.error("{}={}: Unknown option".format(param, value))

                elif param == "pct":
                    self.printer.info("pct={0}: {0}% of received mail is subject to DMARC processing.".format(value))
                    self.__add_commentary("- {}% of emails received would be subject to DMARC processing.".format(value))

                elif param == "aspf":
                    if value == "r":
                        self.printer.warn("aspf=r (Relaxed Mode): Any sub-domains from '{}' are permitted to match DMARC to SPF records.".format(domain))
                        dmarc_vulns.append("Any sub-domains from '.format' are permitted to match DMARC to SPF records.".format(domain))
                    elif value == "s":
                        self.printer.info("aspf=s (Strict Mode): The 'header from' domain and SPF must match exactly to pass DMARC checks.")
                    else:
                        self.printer.error("{}={}: Unknown option.".format(param, value))

                elif param == "rua":
                    for address in [ x.strip() for x in value.split(",") ]:
                        if address[0:7] != "mailto:":
                            self.printer.error("rua=: Aggregate mail reports will not be sent as incorrect syntax is used. Prepend 'mailto:' before mail addresses. '{}'".format(address))
                            self.__add_commentary("- invalid email addresses (i.e. without the prepended 'mailto:') were included in the SPF configuration: '{}'".format(address))
                            dmarc_vulns.append("Invalid email addresses (i.e. without the prepended 'mailto:') were included in the SPF configuration: '{}'".format(address))
                        else:
                            report_addresses.append(address[8:].strip())
                    if len(report_addresses) > 0:
                        self.printer.ok("rua=: Aggregate mail reports will be sent to the following email addresses:\n    {}".format("\n    ".join(report_addresses)))

            if len(report_addresses) > 0:
                self.__add_commentary("\nDMARC email aggregation reports for '{}' were configured to be sent to:\n- {}".format(domain, "\n- ".join(report_addresses)))

            if len(dmarc_vulns) > 0:
                self.__add_vuln(self.src_vulnerabilities["weak-dmarc"], {'domain':self.domain, 'issues':"\n- ".join(dmarc_vulns)})

            return True
        except:
            return False


def main():

    parser = argparse.ArgumentParser(description="""SPF & DMARC record validator, and DKIM key length checker

Checks for and validates SPF and DMARC DNS records. 
Checks for a valid DKIM record, then validates the length of the RSA key.
Either a Domain and optional Selector, or a File (Outlook .msg file) must be provided.
""", formatter_class=argparse.RawTextHelpFormatter)

    group = parser.add_argument_group(title="Domain selection", description="""One of --domain or --file must be set. 
    If --file is used --domain can be set to override the Domain found in the email.
    The selector is optional, but can be specified with --domain (not with --file) to manually set the DKIM selector.""")
    group.add_argument('--domain', '-d', help="Enter the Domain name to verify. E.g. example.com", required=False)
    group.add_argument('--selector', '-s', help="Enter the Selector to verify [default='default']", required=False,
                       default="default")
    group.add_argument('--file', '-f', help="Outlook message file (.msg) to analyse", required=False)

    group2 = parser.add_argument_group(title="Other arguments")
    group2.add_argument('--no-dkim', dest="no_dkim", help="Skip DKIM checks", required=False, action="store_true")
    group2.add_argument('--quiet', '-q', help="Exclude info messages", required=False, action="store_true")
    group2.add_argument('--wrap', '-w', help="Wrap output at ~80 characters", required=False, action="store_true")
    group2.add_argument('--ns', dest="name_server", help="Name server to use instead of network default",
                        required=False, default=None)
    group2.add_argument('--version', action='version', version='%(prog)s {}'.format(__version__))
    args = parser.parse_args()

    if not args.file and not args.domain:
        parser.error("One of --domain or --file is required")
        sys.exit(1)

    wrap_length = 0 if not args.wrap else 80

    if args.file:
        #selector, dkim_domain, domain = extract_mail_headers(args.file)
        analyser = EmailAnalyser(file=args.file, quiet=args.quiet, wrap=wrap_length, ns=args.name_server, domain=args.domain)
    else:
        # selector = args.selector
        # dkim_domain = domain = args.domain
        analyser = EmailAnalyser(domain=args.domain, selector=args.selector, quiet=args.quiet, wrap=wrap_length, ns=args.name_server)

    analyser.check_spf()
    analyser.check_dmarc()
    if not args.no_dkim:
        analyser.check_dkim()


main()
