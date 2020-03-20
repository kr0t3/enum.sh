#!/bin/bash

echo "[i] Online Subdomain Detect Script"
echo ""

#timestamp
fecha=$(date "+%d%m%Y")



if [[ $# -eq 0 ]] ;
then
echo "Easy recon for bugbounty hunters."
echo "Usage :  ./sub.sh test.com"
echo ""
        exit 1
else

		echo "Script running, please wait . . ."
        
        curl -s "http://web.archive.org/cdx/search/cdx?url=*."$1"/*&output=text&fl=original&collapse=urlkey" |sort| sed
-e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | uniq >>$1.txt

                echo "[+] Web.Archive.org [DONE]"

        curl -s "https://dns.bufferover.run/dns?q=."$1 | jq -r .FDNS_A[]|cut -d',' -f2|sort -u >>$1.txt

                echo "[+] Dns.bufferover.run [DONE]"

        curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$1"|jq .subdomains|grep -o "\w.*$1" >>$1.txt

                echo "[+] Threatcrowd.org [DONE]"

        curl -s "https://api.hackertarget.com/hostsearch/?q=$1"|grep -o "\w.*$1" >>$1.txt

                echo "[+] Hackertarget.com [DONE]"

        curl -s "https://certspotter.com/api/v0/certs?domain="$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep $1 >>$1.txt

                echo "[+] Certspotter.com [DONE]"

{
        amass enum --passive -d $1 -json $1.json
        jq .name $1.json | sed "s/\"//g"| uniq | tee -a $1.txt
        rm $1.json
} &> /dev/null
                echo "[+] Amass [DONE]"
{
        subfinder -d $1 | grep $1 |uniq >>$1.txt
} &> /dev/null
                echo "[+] Subfinder [DONE]"
{
        findomain -t $1 -u $1.findomain.txt
        cat $1.findomain.txt | grep $1 |uniq >>$1.txt
} &> /dev/null
                echo "[+] Findomain [DONE]"


        echo "——————————————————————————————————$1 SUBDOMAIN————————————————————————————————————————————"
        cat $1.txt|sort -u|tee -a $1-$fecha.txt
        echo "- - - - - - - - - - - - - - - - - $1 ALIVE SUBDOMAIN - - - - - - - - - - - - - - - - - - -"
        cat $1.txt|httprobe -t 15000 -c 50|cut -d "/" -f3|sort -u |tee alive_$1-$fecha.txt
        echo ""
		echo "Enum Done, now sub.sh going to dirsearch each subdomain saving what it found in a single txt."
		echo "WARNING : I recommend continue this only for short scopes ( 1-10 ) , otherwise it may takes hours (depending of)"
		read -p "Do you want to continue (Y or N) ? " -n 1 -r
		echo    # (optional) move to a new line
		if [[ $REPLY =~ ^[Yy]$ ]]
		then
			#tambien se puede hacer que tire un httprobe | get-title 
			{
			
				for i in $() do
					gobuster 
				done
				python3 ~/tools/dirsearch/dirsearch.py -L  alive_$1-$fecha.txt -x 502,403 -t 50 -b -e * >> dirsearch_$1-$fecha.txt 
			} &> /dev/null
			
		fi

fi
