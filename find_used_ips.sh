#! /bin/sh

# Author: b4dpxl
# Run all the arp-scan options to try and find IP's in use for a given range
# Note, you still need an idea of the IP range. Use tcpdump:
#  tcpdump -li eth0 arp | grep -Po "(?<=tell )(\d{1,3}\.){3}\d{1,3}"
#
# All credit goes to Encription and http://pentestmonkey.net/blog/the-science-of-safely-finding-an-unused-ip-address
# for showing me how to do this. I just scripted it.

NIC=eth2

# check it's probably an IP (basic regex)
if ! echo $1 | grep -P "(\d{1,3}\.){3}\d{1,3}" > /dev/null ; then
	echo "Usage: $0 <target_IP_range>"
	echo "  Note, run an ARP scan to find a possible target range"
	exit 1
fi

bin=tempfile
if ! which $bin > /dev/null 2>&1 ; then
	# Fedora doesn't have tempfile
        bin=mktemp
fi

f=`$bin`
touch $f
> $f

for src in 127.0.0.1 0.0.0.0 255.255.255.255 1.0.0.1 ; do
	echo "Scanning with $src"
	arp-scan -I $NIC --arpspa $src $1 >> $f
done

grep -P "^(\d{1,3}\.){3}\d{1,3}" $f | awk '{print $1}' | sort -V | uniq
