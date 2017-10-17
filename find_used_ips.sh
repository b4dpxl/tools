#! /bin/sh

# Author: b4dpxl
# Run all the arp-scan options to try and find IP's in use for a given range
# Note, you still need an idea of the IP range. Use tcpdump:
#  tcpdump -li eth0 arp | grep -Po "(?<=tell )(\d{1,3}\.){3}\d{1,3}"

# check it's probably an IP (basic regex)
if ! echo $1 | grep -P "(\d{1,3}\.){3}\d{1,3}" > /dev/null ; then
	echo "Usage: $0 <target_IP_range>"
	echo "  Note, run an ARP scan to find a possible target range"
	exit 1
fi

f=`tempfile`
> $f
for src in 127.0.0.1 0.0.0.0 255.255.255.255 1.0.0.1 ; do
	echo "Scanning with $src"
	arp-scan -I eth0 --arpspa $src $1 >> $f
done

grep -P "^(\d{1,3}\.){3}\d{1,3}" $f | awk '{print $1}' | sort -V | uniq
