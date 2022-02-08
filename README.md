# tools
Miscellaneous tools with no better location.

## email_spoof_header_checker.py
SPF, DMARC, and DKIM record checker. Replaces dkim_key_length_check.py

## __printer.py
Generic class for printing formatted text in python. Used by the other python scripts

## dkim_key_length_check.py
Checks DKIM key length from a file. Use Run-DMC2.py instead

## find_used_ips.sh
Script to find used (and thus unused) IP addresses for a network range from ARP scans

## ip_to_domain.py
Uses various methods to try and determine the hostname for a given IP address

## invoke-mimikatz_parser.py ##
Parse Invoke-Mimikatz.ps1 output files, extracting usernames, hashes, and passwords

## pass2pie.py
Takes a password list and generates human readable and CSV output of common passwords, the latter useful for generating charts in Excel

## pyDNS.py
DNS server which redirects requests for specified domains to another IP. Returns the correct response for all other domains

## pyDNSExfiltrateD.py
Script to act as a DNS listener, and record the lookups to a log file with timestamp & source nameserver IP. Useful for exfiltrating data via DNS

## search_domain.sh
Search a directory of data breaches for a given domain name and extract unique email addresses

## set_cf_ip.py
Updates all A-records for specific CloudFlare DNS zones (domain names) to the current IP address. Useful for setting as a boot script on DigitalOcean droplets

## SimpleDNSServer.py
Simple DNS server. Responds to any request with the specified IP address

## subdomain_hijack_checker.py
Check a domain or series of domains for vulnerabilty to [subdomain hijacking](https://book.hacktricks.xyz/pentesting-web/domain-subdomain-takeover)

## subdomain_hijack_checker_mt.py
Multi-threaded version of `subdomain_hijack_checker.py`

## tls_server.py
Start a SSl/TLS listener with your choice of protocol. Useful for testing protocol version support. The protocol versions supported are reliant on the version of OpenSSL available on the host.

## urlhost.py
Works the same as the generic `host` command, but handles URLs. Handy for when copy/pasting from a browser

## username_generator.py
Generate various permutations of username for a given first and last name.

## requirements.txt
Python PIP requirements.txt file. Covers all scripts (unless I've missed any), so may introduce unecessary packages if you only want a specific script
