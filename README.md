# tools
Miscellaneous tools with no better location.

## Run-DMC2.py
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

## pyDNSExfiltrateD.py
Script to act as a DNS listener, and record the lookups to a log file with timestamp & source nameserver IP. Useful for exfiltrating data via DNS

## search_domain.sh
Search a directory of data breaches for a given domain name and extract unique email addresses

## set_cf_ip.py
Updates all A-records for specific CloudFlare DNS zones (domain names) to the current IP address. Useful for setting as a boot script on DigitalOcean droplets

## SimpleDNSServer.py
Simple DNS server. Responds to any request with the specified IP address

## requirements.txt
Python PIP requirements.txt file. Covers all scripts (unless I've missed any), so may introduce unecessary packages if you only want a specific script
