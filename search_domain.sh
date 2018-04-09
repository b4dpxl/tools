#! /bin/sh

usage() {
	echo "Search data breaches for a given domain name"
	echo "Assumes the file or folder name represents the breach name, and that files are gzipped"
	echo "Searches folders then files in order"
	echo ""
        echo "Usage: $0 -o <output directory> -d <domain name> [-b <breaches directory>]" 1>&2
	echo "Breaches directory defaults to '.'"
        exit 1
}

BREACH_DIR=`readlink -f .`
while getopts ":o:d:b:h" opt ; do
        case $opt in
                o)
			TMP=`readlink -f "$OPTARG"`
                        if [ ! -d "$TMP" ] ; then
                                echo "Invalid output directory"
                                exit 2
                        fi
                        OUT_DIR="$TMP"
                        ;;
                d)
                        DOMAIN="$OPTARG"
                        ;;
		
		b)
			TMP=`readlink -f "$OPTARG"`
                        if [ ! -d "$TMP" ] ; then
                                echo "Invalid breaches directory"
                                exit 2
                        fi
			BREACH_DIR="$TMP"
			;;

                h)
                        usage
                        ;;
        esac
done

if [ -z "$OUT_DIR" ] || [ -z "$DOMAIN" ] ; then
        usage
fi

RED=$(tput setaf 9)
GRN=$(tput setaf 10)
YLW=$(tput setaf 11)
BLU=$(tput setaf 12)
NC=$(tput sgr0)
BOL="$(tput el1)$(tput cup 99)" # clear to beginning of line, move cursor left 99
WIDTH=25

print_result() {
	cnt=`wc -l $1 | awk '{print $1}'`
	if [ $cnt -gt 0 ] ; then
		printf "${BOL}${RED}[+]${NC} %-${WIDTH}.${WIDTH}s %s matches\n" "$2" "$cnt"
	else
		printf "${BOL}${GRN}[-]${NC} %-${WIDTH}.${WIDTH}s No matches\n" "$2"
	fi

}

echo "${BLU}[*]${NC} Checking breaches in ${BREACH_DIR}"

> "${OUT_DIR}/breaches.txt"
cd ${BREACH_DIR}

find . -maxdepth 1 -type d -print | while read dir ; do 
	dir=`echo "$dir" | cut -c 3-`
	if [ ! -z "$dir" ] ; then
		echo -n "[ ] Checking $dir..."
		out=`mktemp`
		find "$dir" -type f -exec zgrep -PHi "\b${DOMAIN}" "{}" \; > "$out"
		print_result "$out" "$dir"
		cat "$out" >> ${OUT_DIR}/breaches.txt
		rm -f "$out"
	fi
done
for file in /*.gz ; do 
	f=`echo "$file" | awk -F'.' '{print $1}' | sed -e 's/_/ /g'`
	echo -n "[ ] Checking $f...\t"
	out=`mktemp`
	zgrep -PHi "\b${DOMAIN}" "$file" > "$out"
	cat "$out" >> ${OUT_DIR}/breaches.txt
	print_result "$out" "$f"
	rm -f "$out"
done

cd -

grep -ioP "\b[a-z]\w+(\.\w+)*?@${DOMAIN}" "${OUT_DIR}/breaches.txt" | sort -u | uniq -i > "${OUT_DIR}/found_emails.txt"
cnt=`wc -l "${OUT_DIR}/found_emails.txt" | awk '{print $1}'`
if [ $cnt -gt 0 ] ; then
	echo "${RED}[+]${NC} Found $cnt unique email addresses"
	echo "    See '${OUT_DIR}/found_emails.txt' and '${OUT_DIR}/breaches.txt'"
else
	echo "${GRN}[-]${NC} Found no valid email addresses in any breaches"
fi
