#! /bin/sh

usage() {
    echo "Usage: $0 WORDLIST_DIR URL"
    exit 1
}

WL=$1
URL=$2

if [ -z "$URL" ] || [ -z "$WL" ] || [ ! -d "$WL" ]; then usage ; fi

out=gobuster-`echo "$URL" | sed -r 's/^https?:\/\///' |sed -r 's/\W+/_/g'`.txt

for w in /pentest_d/wordlists/api_wordlist/*.txt ; do 
    gobuster dir -w "$w" -t 3 -u "$URL"  -s "200,204,301,302,307,401,403,405" 
done | tee $out
