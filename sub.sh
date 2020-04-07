#!/bin/bash

#timestamp
fecha=$(date "+%d%m%Y")
#colour
bold=`echo -en "\e[1m"`; underline=`echo -en "\e[4m"`; dim=`echo -en "\e[2m"`; strickthrough=`echo -en "\e[9m"`; blink=`echo -en "\e[5m"`; reverse=`echo -en "\e[7m"`; hidden=`echo -en "\e[8m"`; normal=`echo -en "\e[0m"`; black=`echo -en "\e[30m"`; red=`echo -en "\e[31m"`; green=`echo -en "\e[32m"`; orange=`echo -en "\e[33m"`;  blue=`echo -en "\e[34m"`; purple=`echo -en "\e[35m"`; aqua=`echo -en "\e[36m"`; gray=`echo -en "\e[37m"`; darkgray=`echo -en "\e[90m"`; lightred=`echo -en"\e[91m"`; lightgreen=`echo -en "\e[92m"`; lightyellow=`echo -en "\e[93m"`; lightblue=`echo -en "\e[94m"`; lightpurple=`echo -en "\e[95m"`; lightaqua=`echo -en "\e[96m"`; white=`echo -en "\e[97m"`; default=`echo -en "\e[39m"`; BLACK=`echo -en "\e[40m"`; RED=`echo -en "\e[41m"`; GREEN=`echo -en "\e[42m"`; ORANGE=`echo -en "\e[43m"`; BLUE=`echo -en "\e[44m"`; PURPLE=`echo -en "\e[45m"`; AQUA=`echo -en "\e[46m"`; GRAY=`echo -en "\e[47m"`; DARKGRAY=`echo -en "\e[100m"`; LIGHTRED=`echo -en"\e[101m"`; LIGHTGREEN=`echo -en "\e[102m"`; LIGHTYELLOW=`echo -en "\e[103m"`; LIGHTBLUE=`echo -en "\e[104m"`; LIGHTPURPLE=`echo -en "\e[105m"`; LIGHTAQUA=`echo -en "\e[106m"`; WHITE=`echo -en "\e[107m"`; DEFAULT=`echo -en "\e[49m"`;

#install req tools / addons before use. See  readme.md for more information.

{
	if [ ! -f /scripts/alert]; then
		echo "File not found!"
		exit 0
	fi
}


if [[ $# -eq 0 ]] ;
then
	echo -e $red
	echo -e "        +@'WWWWWW#%:."
	echo -e "       &@'/        ':+."
	echo -e "     e@'/___________\@"
	echo -e "    e@@@@@@@@@@@@@@@//"
	echo -e "   e@/'------------/"
	echo -e "  :@/                "
	echo -e " @b'\_____________/ "
	echo -e "  @b\wwwwwwwwwww#/  "
	echo $green"[i]"$normal $red$WHITE"Easy recon for bugbounty hunters."$normal
	echo ""
	echo "Usage : ./sub.sh test.com"
	echo "ver.0.5"
	exit 1
	else
	echo "[+] Script running, please wait."

					echo -ne '['$green'#'$normal'====================](0%)\r'
					sleep 1

				{
					curl -s "http://web.archive.org/cdx/search/cdx?url=*."$1"/*&output=text&fl=original&collapse=urlkey" |sort| sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | uniq >>$1.txt
				} &> /dev/null

				echo -ne '['$green'######'$normal'===============](25%)\r'
				{
					amass enum --passive -d $1 -json $1.json
					jq .name $1.json | sed "s/\"//g"| uniq | tee -a $1.txt
					rm $1.json
				} &> /dev/null

				echo -ne '['$green'############'$normal'==========](50%)\r'
				{
					subfinder -d $1 | grep $1 |uniq >>$1.txt
				} &> /dev/null
				echo -ne '['$green'#################'$normal'=====](75%)\r'

				{
					findomain -t $1 -u $1.findomain.txt
					cat $1.findomain.txt | grep $1 |uniq >>$1.txt
				} &> /dev/null

				echo -ne '['$green'#######################'$normal'](100%) DONE\r'
				sleep 1
				echo ""
				cat $1.txt|sort -u > $1-$fecha.txt
				echo "- - - - - - - - - - - - - - - - - $1 ALIVE SUBDOMAIN - - - - - - - - - - - - - - - - - - -"
				#cat $1.txt|httprobe -t 15000 -c 50|cut -d "/" -f3|sort -u |tee alive_$1-$fecha.txt
				cat $1.txt|fprobe|cut -d "/" -f3|sort -u |tee alive_$1-$fecha.txt
				echo ""
fi



	echo "[1] Nmap top 500 to alive_"$1"-"$fecha".txt"
	echo "[2] History of site dns"
	echo "[3] Deadpage (if error json = 404)"
	echo "[4] CeWL (Generate wordlist from root domain/subdomain)"
	echo "[5] Scan for backups"
	echo ""
	read -p "Pick an option " -n 1 -r

								if [[ $REPLY =~ ^[1]$ ]]
								then
												#Nmap top 500
												for i in $(cat alive_$1-$fecha.txt); do nmap $i --top-ports 500 --min-rate 10 ; done
								fi
								if [[ $REPLY =~ ^[2]$ ]]
								then
												#History of Site
												for i in $(cat alive_$1-$fecha.txt); do curl --silent https://securitytrails.com/domain/$1/history/a |  pup -i 4 'tr[class=data-row] div text{}' | grep '\S'; done
								fi
								if [[ $REPLY =~ ^[3]$ ]]
								then
												#Deadpage
												for i in $(cat alive_$1-$fecha.txt); do  echo $1 | gau -subs | concurl -c 20 -- -s -L -o /dev/null -k -w '%{http_code},%{size_download}'; done
								fi
								if [[ $REPLY =~ ^[4]$ ]]
								then
									#generate an dicctionary
												for i in $(cat alive_$1-$fecha.txt); do 	~/tools/CeWL/cewl.rb $i >> $i-wordlist.txt; done
								fi
								if [[ $REPLY =~ ^[5]$ ]]
								then
									#search for backups
									for i in $(cat alive_$1-$fecha.txt); do ~/tools/ohmybackup/ohmybackup $i; done
								fi
