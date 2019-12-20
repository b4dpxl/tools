#! /bin/sh
usage() {
        echo "Usage: $0 -v host -u user [-p passwd]" 1>&2
        exit 1
}
while getopts ":v:u:p:h" opt ; do
        case $opt in
                v)
                        HOST="$OPTARG"
                        ;;
                u)
                        USER="$OPTARG"
                        ;;
                p)
                        PASSWD="$OPTARG"
                        ;;
        esac
done
if [ -z "$USER" ] || [ -z "$HOST" ] ; then
        usage
fi
if [ -z "$PASSWD" ] ; then
        read -p "Password: " PASSWD
fi
xfreerdp /w:1280 /h:960 /cert-tofu /v:$HOST /u:$USER /p:$PASSWD &

