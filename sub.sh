#!/bin/bash

#	This tool is presented 'as is' and throuh the time will be improved up.
#nwo
#					version 0.6.010420 										:) <3 Ty
#
#	Please if you like it give me more ideas to make it better.
#
#
# Next update: parameters.. ./tool -u example.com | ./tool -m (for menu)

fecha=$(date "+%d%m%Y")
lightyellow=`echo -en "\e[93m"`;red=`echo -en "\e[31m"`;green=`echo -en "\e[32m"`;normal=`echo -en "\e[0m"`;WHITE=`echo -en "\e[107m"`;

#install req tools / addons before use. See  readme.md for more information.

dominio=$1

	echo -e $red
	echo -e "        +@'WWWWWW#%:."
	echo -e "       &@'/        ':+."
	echo -e "  __ e@'/___________\@"
	echo -e "  ##e@#/;'__0.6__###/"            $red$WHITE"Easy recon"$normal$red
	echo -e "   e@/"								$red$WHITE "for"$normal$red
	echo -e "  :@/        "					$red$WHITE "BugHunters."$normal$red
	echo -e " @b'\______________ "
	echo -e "  @b\wwwwwwwwwwwww/  "
	echo
	echo ""
	echo "$green"[i]"$normal $lightyellow Usage : ./enum.sh example.com"$normal
	echo ""


proceso(){
					echo -ne '['$green'#'$normal'====================](0%)\r'
					sleep 1

				{
					curl -s "http://web.archive.org/cdx/search/cdx?url=*."$dominio"/*&output=text&fl=original&collapse=urlkey" |sort| sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | uniq >>$dominio.txt
				} &> /dev/null

				echo -ne '['$green'######'$normal'===============](25%)\r'
				{
					amass enum --passive -d $dominio -json $dominio.json
					jq .name $dominio.json | sed "s/\"//g"| uniq | tee -a $dominio.txt
					rm $dominio.json
				} &> /dev/null

				echo -ne '['$green'############'$normal'==========](50%)\r'
				{
					subfinder -d $dominio | grep $dominio |uniq >>$dominio.txt
				} &> /dev/null
				echo -ne '['$green'#################'$normal'=====](75%)\r'

				{
					findomain -t $dominio -u $dominio.findomain.txt
					cat $dominio.findomain.txt | grep $dominio |uniq >>$dominio.txt
				} &> /dev/null

				echo -ne '['$green'#######################'$normal'](100%) DONE\r'
				cat $dominio.txt|sort -u >> $dominio-$fecha.txt
				#cat $dominio.txt|fprobe|cut -d "/" -f3|sort -u | tee alive_$dominio-$fecha.txt
				cat $dominio.txt|httprobe -t 15000 -c 50|cut -d "/" -f3|sort -u |tee alive_$dominio-$fecha.txt
				echo ""
				menu
}


menu(){
	echo "[0] Scan again."
	echo "[1] Nmap top 500 to alive_"$dominio"-"$fecha".txt"
	echo "[2] History of site dns"
	echo "[3] Deadpage (if error json = 404)"
	echo "[4] CeWL (Generate wordlist from root domain/subdomain)"
	echo "[5] dirsearch all subdomains, default wordlist (6.3k) (may it take long.)Please try the generated one from step 4 too."
	echo "[enter] Exit"
	read -p "Pick an option: " -n 0 -r
								if [[ $REPLY =~ ^[0]$ ]]
								then
									proceso
								fi
								if [[ $REPLY =~ ^[1]$ ]]
								then
												#Nmap top 500
												for i in $(cat alive_$dominio-$fecha.txt); do nmap $i --top-ports 500 --min-rate 10 -Pn; done
												menu
								fi
								if [[ $REPLY =~ ^[2]$ ]]
								then
												#History of Site
												for i in $(cat alive_$dominio-$fecha.txt); do echo "Target: "$i && curl --silent https://securitytrails.com/domain/$i/history/a |  pup -i 4 'tr[class=data-row] div text{}' | grep '\S'; done
												menu
								fi
								if [[ $REPLY =~ ^[3]$ ]]
								then
												#Deadpage (all good until here)
												for i in $(cat alive_$dominio-$fecha.txt); do  echo $i | gau -subs | concurl -c 20 -- -s -L -o /dev/null -k -w '%{http_code},%{size_download}' >> deagpage-$dominio-$fecha.txt; done
												menu
								fi
								if [[ $REPLY =~ ^[4]$ ]]
								then
									#generate an dicctionary
												for i in $(cat alive_$dominio-$fecha.txt); do 	~/tools/CeWL/cewl.rb $i >> $dominio-wordlist.txt; done
												menu
								fi
								if [[ $REPLY =~ ^[5]$ ]]
								then
									#Dirsearch every subdomain , default wordlist (it takes long)
									echo "running dirsearch, please wait.."
									touch dirsearch-$dominio.txt
									tail -f dirsearch-$dominio.txt
									#{
												for i in $(cat alive_$dominio-$fecha.txt); do python3 ~/tools/dirsearch/dirsearch.py -e html -u ${i} >> dirsearch-${i}.txt; done
									#} &> /dev/null
									echo "Done."
									menu
								fi
}

if [[ $# -eq 0 ]]; then
	exit 0
	elif [ ! -f ~/github/enum.sh/$1.txt ]; then
		echo "[+] Script running, please wait."
		proceso
	else
		echo "Domain already scanned, skipping to menu"
		echo "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
		echo ""
		menu
	fi
}





#es mejor usar FFUF.
