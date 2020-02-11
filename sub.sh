#!/bin/bash

echo "[i] Online Subdomain Detect Script"
echo "[t] Twitter => https://twitter.com/cihanmehmets"
echo "[g] Github => https://github.com/cihanmehmet"
echo "[#] curl -sL https://raw.githubusercontent.com/cihanmehmet/sub.sh/master/sub.sh | bash -s bing.com"
echo "[#] curl -sL https://git.io/JesKK | bash -s tesla.com"
echo "███████████████████████████████████████████████████████████████████████████████████████████████"

checkArgs(){
    if [[ $# -eq 0 ]]; then
        echo -e "[+] Usage: command test.com"
        exit 1
    fi
}

#timestamp
fecha=$(date "+%d%m%Y")



inicio(){
        curl -s "https://crt.sh/?q=%25."$1"&output=json"| jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u|grep -o "\w.*$1" > $1.txt

                echo "[+] Crt.sh Over"

        curl -s "http://web.archive.org/cdx/search/cdx?url=*."$1"/*&output=text&fl=original&collapse=urlkey" |sort| sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | uniq >>$1.txt

                echo "[+] Web.Archive.org Over"

        curl -s "https://dns.bufferover.run/dns?q=."$1 | jq -r .FDNS_A[]|cut -d',' -f2|sort -u >>$1.txt

                echo "[+] Dns.bufferover.run Over"

        curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$1"|jq .subdomains|grep -o "\w.*$1" >>$1.txt

                echo "[+] Threatcrowd.org Over"

        curl -s "https://api.hackertarget.com/hostsearch/?q=$1"|grep -o "\w.*$1" >>$1.txt

                echo "[+] Hackertarget.com Over"

        curl -s "https://certspotter.com/api/v0/certs?domain="$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep $1 >>$1.txt

                echo "[+] Certspotter.com Over"

	{
        amass enum --passive -d $1 -json $1.json
        jq .name $1.json | sed "s/\"//g"| uniq | tee -a $1.txt
        rm $1.json
	} &> /dev/null

		echo "[+] Amass Over"
	{
        subfinder -d $1 | grep $1 |uniq >>$1.txt
	} &> /dev/null
        
		echo "[+] Subfinder Over"
	{
        findomain -t $1 -u $1.findomain.txt
        cat $1.findomain.txt | grep $1 |uniq >>$1.txt
	} &> /dev/null
        
		echo "[+] Findomain Over"


        echo "——————————————————————————————————$1 SUBDOMAIN————————————————————————————————————————————"
        cat $1.txt|sort -u|tee -a $1-$fecha.txt
        echo "- - - - - - - - - - - - - - - - - $1 ALIVE SUBDOMAIN - - - - - - - - - - - - - - - - - - -"
        cat $1.txt|httprobe -t 15000 -c 50|cut -d "/" -f3|sort -u |tee alive_$1-$fecha.txt
        echo ""
        echo "███████████████████████████████████████████████████████████████████████████████████████████"
        echo "Detect Subdomain $(wc -l $1-$fecha.txt|awk '{ print $1 }' )" "=> ${1}"
        echo "File Location : "$(pwd)/"$1-$fecha.txt"
        echo ""
        echo "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓"
        echo "Detect Alive Subdomain $(wc -l alive_$1-$fecha.txt|awk '{ print $1 }' )" "=> ${1}"
        echo "File Location : "$(pwd)/"alive_$1-$fecha.txt"
		
		echo ""
		echo ""
		echo ""
		echo "PART 2 of RECON"
		echo ""
		echo ""
		echo ""
		
		python3 /home/krossom/tools/github-subdomains.py -d $1 -s  -t e69d68b0ad6eeafa8e00879e5563cbfbaa80a653 >> github-$1-$fecha.txt
		
}		
		
waf(){
	wafw00f -l $1.txt >>waf.txt 	  &> /dev/null
	echo "WAF found: " && cat waf.txt
}		
		
takeover(){		
	echo -e "[ Checking for subdomain takeovers ]"
		
	~/go/bin/subjack -a -ssl -t 50 -v -c ~/go/src/github.com/haccer/subjack/fingerprints.json -w $1.txt -o final-takeover.tmp
    cat final-takeover.tmp | grep -v "Not Vulnerable" > final-takeover.txt
    rm final-takeover.tmp
    echo -e "[*] Check subjack's result at final-takeover.txt"
	
	
	
	
	
	
	
	
	
	
	
	
	
	#AGREGAR TODOS LOS SUBDOMAIN TOOLS A ESTA WEA
}	

corsScan(){
    echo -e "${GREEN}\n--==[ Checking CORS configuration ]==--${RESET}"
    runBanner "CORScanner"
    python $TOOLS_PATH/CORScanner/cors_scan.py -v -t 50 -i $SUB_PATH/final-subdomains.txt | tee $CORS_PATH/final-cors.txt
    echo -e "${BLUE}[*] Check the result at $CORS_PATH/final-cors.txt${RESET}"
}


enumIPs(){
    echo -e "${GREEN}\n--==[ Resolving IP addresses ]==--${RESET}"
    runBanner "massdns"
    $TOOLS_PATH/massdns/bin/massdns -r $TOOLS_PATH/massdns/lists/resolvers.txt -q -t A -o S -w $IP_PATH/massdns.raw $SUB_PATH/final-subdomains.txt
    cat $IP_PATH/massdns.raw | grep -e ' A ' |  cut -d 'A' -f 2 | tr -d ' ' > $IP_PATH/massdns.txt
    cat $IP_PATH/*.txt | sort -V | uniq > $IP_PATH/final-ips.txt
    echo -e "${BLUE}[*] Check the list of IP addresses at $IP_PATH/final-ips.txt${RESET}"
}


##
#aca  se podria agregar el naabu para no sacar las ip
# o usar las dos weas
#
		
		
		
bruteDir(){
    echo -e "${GREEN}\n--==[ Bruteforcing directories ]==--${RESET}"
    runBanner "dirsearch"
    echo -e "${BLUE}[*]Creating output directory...${RESET}"
    mkdir -p $DIR_PATH/dirsearch
    for url in $(cat $SSHOT_PATH/aquatone/aquatone_urls.txt); do
        fqdn=$(echo $url | sed -e 's;https\?://;;' | sed -e 's;/.*$;;')
        $TOOLS_PATH/dirsearch/dirsearch.py -b -t 100 -e php,asp,aspx,jsp,html,zip,jar,sql -x 500,503 -r -w $WORDLIST_PATH/raft-large-words.txt -u $url --plain-text-report=$D>        if [ ! -s $DIR_PATH/dirsearch/$fqdn.tmp ]; then
            rm $DIR_PATH/dirsearch/$fqdn.tmp
        else
            cat $DIR_PATH/dirsearch/$fqdn.tmp | sort -k 1 -n > $DIR_PATH/dirsearch/$fqdn.txt
            rm $DIR_PATH/dirsearch/$fqdn.tmp
        fi
    done
    echo -e "${BLUE}[*] Check the results at $DIR_PATH/dirsearch/${RESET}"
}



deadpage(){
    echo $1 | gau -subs | concurl -c 20 -- -s -L -o /dev/null -k -w '%{http_code},%{size_download}'
} &> /dev/null

sslvuln(){
	python /home/krossom/tools/a2sv/a2sv.py -tf $1.txt | grep Vulnerable! >> $1-sslvuln.txt | &>dev/null
	echo -ne "[*] a2sv over. SSL Vulnerable found: \b " && cat $1-sslvuln.txt | wc -l
} 


#altdns(){
	#altdns -i $1.txt -o data_output -w words.txt -r -s results_output.txt  &> /dev/null
	echo "altDNS done"
#-w words.txt puede ser generado a partir de la herramineta del th3g3ntl3m3n para generar words a partir de subdominio.
#}

#arjun(){
	#python3 ~/tools/Arjun/arjun.py --urls $1.txt --get  &> /dev/null
	echo "arjun done"
#}


bfac(){
	python3 /home/krossom/tools/bfac/bfac -L $1.txt  &> /dev/null
	echo bfac done
}



inicio
checkArgs $1
takeover
waf
corsScan
enumIPs
bruteDir
deadpage
sslvuln
#altdns
bfac

echo "--==[ DONE ]==--"
