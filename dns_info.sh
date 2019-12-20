#! /bin/sh

GRN='\033[1;32m' # light green
RED='\033[1;31m' # light red
BLU='\033[1;34m' # light blue
NC='\033[0m' # No Color
BOL='\e[0K\r' # beginning of line

OUT_FILE=""

ok() {
    echo -e "${GRN}[+]${NC} $1"
    echo "$1" >> "$OUT_FILE"
}

fail() {
    echo -e "${RED}[-]${NC} $1"
    echo "$1" >> "$OUT_FILE"
}

info() {
    echo -e "${BLU}[*]${NC} $1"
    echo "$1" >> "$OUT_FILE"
}

print() {
    echo "$1"
    echo "$1" >> "$OUT_FILE"
}

usage() {
        echo "Usage: $0 -o <output directory> -d <domain name>" 1>&2
        exit 1
}

while getopts ":o:d:h" opt ; do
        case $opt in
                o)
                        if [ ! -d "$OPTARG" ] ; then
                                echo "Invalid output directory"
                                exit 2
                        fi
                        OUT_DIR=`readlink -f "$OPTARG"`
                        OUT_FILE="$OUT_DIR/results.txt"
                        > "$OUT_FILE"
                        ;;
                d)
                        DOMAIN="$OPTARG"
                        ;;
                -h)
                        usage
                        ;;
        esac
done

if [ -z "$OUT_DIR" ] || [ -z "$DOMAIN" ] ; then
        usage
fi

DC_file=`mktemp`
#dig srv _ldap._tcp.dc._msdcs.${DOMAIN} | grep -P "IN\s+A\s+(\d+\.){3}\d+" | awk '{print $5}' > $DC_file
nslookup $DOMAIN | grep -P "Address: \d+" | awk '{print $2}' > $DC_file
info "DOMAIN CONTROLLERS"
for ip in `cat "$DC_file" | sort -V` ; do
	ok "$ip"
done
print "###"
print ""


info "DNS TRANSFERS"
for ip in `cat "$DC_file" | sort -V` ; do
	info "Trying $ip"
	o=`mktemp`
	dig @${ip} ${DOMAIN}  axfr 2>&1 | tee "$o"
	if grep -iq "transfer failed" "$o" ; then
		fail "Transfer failed"
	fi
	print ""
done
print "###"
print ""

info "TXT RECORDS"
for ip in `cat $DC_file | sort -V` ; do
	info "Trying $ip"
	res=`dig txt @${ip} $DOMAIN 2>/dev/null | grep -v "^;" | grep -Po "\bTXT.*$"`
	if [ -z "$res" ] ; then
        fail "No TXT records"
    fi
    for txt in $res ; do
        ok $txt
    done
	print ""
done
print "###"
print ""

info "REVERSE DNS"
o=`mktemp`
cat $DC_file | sed -e 's/\.[0-9]*$//g' | sort -V | uniq > "$o"
for range in `cat "$o"` ; do
	info "Trying $range.0/24"
    /opt/dnsrecon/dnsrecon.py -t rvl -r ${range}.0/24 > "$OUT_DIR/rdns_$range.0-24.txt" 2>/dev/null
    cat "$OUT_DIR/rdns_$range.0-24.txt" | grep -Po "(?<=\bPTR\s).*$" | while read dns ; do
        ok "$dns"
    done
done

cat "$OUT_DIR/rdns_*" | grep "PTR" | awk '{printf( "%s\t%s\n", $3, $4 )}' | sort > "$OUT_DIR/rdns_namesorted.txt"
cat "$OUT_DIR/rdns_*" | grep "PTR" | awk '{printf( "%s\t%s\n", $4, $3 )}' | sort -V > "$OUT_DIR/rdns_ipsorted.txt"
print "###"

echo "See $OUT_FILE for a copy of the results"
