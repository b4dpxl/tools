#! /bin/sh

# Author: b4dpxl
# Run all the arp-scan options to try and find IP's in use for a given range
# Note, you still need an idea of the IP range. Use tcpdump:
#  tcpdump -li eth0 arp | grep -Po "(?<=tell )(\d{1,3}\.){3}\d{1,3}"
#
# All credit goes to Encription and http://pentestmonkey.net/blog/the-science-of-safely-finding-an-unused-ip-address
# for showing me how to do this. I just scripted it.

RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[0;33m'
NC='\033[0m' # No Color

usage() {
	echo -e "${YEL}[*]${NC} Usage: $0 <target_IP_range> <interface>"
	echo "    Note, run an ARP scan to find a possible target range"
	exit 1
}

bin=tempfile
if ! which $bin > /dev/null 2>&1 ; then 
	bin=mktemp
fi

# check it's probably an IP (basic regex)
if ! echo $1 | grep -P "(\d{1,3}\.){3}\d{1,3}" > /dev/null ; then
	echo -e "${RED}[!]${NC} Invalid IP range specified"
	usage
fi

if ! ifconfig $2 > /dev/null || [ "x$2" == "x" ]; then
	echo -e "${RED}[!]${NC} Invalid interface specified"
	usage
fi

f=`$bin`
echo $f
> $f
for src in 127.0.0.1 0.0.0.0 255.255.255.255 1.0.0.1 ; do
	echo "Scanning with $src"
	arp-scan -I $2 --arpspa $src $1 >> $f
done

if grep -P "^(\d{1,3}\.){3}\d{1,3}" $f ; then
	echo -e "${GRN}[+]${NC} Found used IP addresses"
	grep -P "^(\d{1,3}\.){3}\d{1,3}" $f | awk '{print $1}' | sort -V | uniq
else
	echo -e "${YEL}[~]${NC} No IP addresses found"
fi

