#!/bin/bash
echo "[i] Online Subdomain Detect Script"
echo ""
#timestamp
fecha=$(date "+%d%m%Y")

 if [[ $# -eq 0 ]] ;
then
echo "Easy recon for bugbounty hunters."
echo "Usage : ./sub.sh test.com"
echo "ver. 0.4"
        exit 1
else


echo "[+] Script running, please wait."

        echo -ne '[#====================](0%)\r'
        sleep 1
{
        curl -s "http://web.archive.org/cdx/search/cdx?url=*."$1"/*&output=text&fl=original&collapse=urlkey" |sort| sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^w
ww\.//' | uniq >>$1.txt
} &> /dev/null

        echo -ne '[######===============](25%)\r'
{
        amass enum --passive -d $1 -json $1.json
        jq .name $1.json | sed "s/\"//g"| uniq | tee -a $1.txt
        rm $1.json
} &> /dev/null

        echo -ne '[############==========](50%)\r'
{
        subfinder -d $1 | grep $1 |uniq >>$1.txt
} &> /dev/null
        echo -ne '[#################=====](75%)\r'
{
        findomain -t $1 -u $1.findomain.txt
        cat $1.findomain.txt | grep $1 |uniq >>$1.txt
} &> /dev/null

        echo -ne '[#######################](100%) DONE\r'
sleep 1
        echo "$1 SUBDOMAIN"

        cat $1.txt|sort -u|tee -a $1-$fecha.txt
        echo "- - - - - - - - - - - - - - - - - $1 ALIVE SUBDOMAIN - - - - - - - - - - - - - - - - - - -"
        cat $1.txt|httprobe -t 15000 -c 50|cut -d "/" -f3|sort -u |tee alive_$1-$fecha.txt
        echo ""
fi
