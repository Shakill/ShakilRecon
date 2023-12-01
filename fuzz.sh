#!/bin/bash
 
#colors
red=`tput setaf 1`
green=`tput setaf 2`
yellow=`tput setaf 3`
blue=`tput setaf 4`
magenta=`tput setaf 5`
reset=`tput sgr0`
 
read -p "Enter domain name : " domain


if [ -d /root/recon/$domain/Content_Discovery ]
then
  echo " "
else
  mkdir /root/recon/$domain/Content_Discovery
 
fi
 
 
echo "${blue} [+] Started Content Discovery Scanning ${reset}"
echo " "

#wordlist
echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"
echo " "
if [ -f /root/wordlist/mrco24-wordlist/'Critical word big.txt' ]
then
 echo " "
else
 echo "${blue} [+] Downloading wordlists ${reset}"
 wget https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt -P ~/Desktop/tools/
fi

#feroxbuster
if [ -f /usr/bin/feroxbuster ]
then
 echo "${magenta} [+] Running Feroxbuster for content discovery${reset}"
 for url in $(cat /root/recon/$domain/subdomain/good/active_subdomain.txt);do
 reg=$(echo $url | sed -e 's;https\?://;;' | sed -e 's;/.*$;;')
 feroxbuster --url $url -w /root/wordlist/mrco24-wordlist/'Critical word big.txt'  -x php asp aspx jsp py txt conf config bak backup swp old db zip sql --depth 3 --threads 300 --output /root/recon/$domain/Content_Discovery/content_discovery_result.txt
done
else
 echo "${blue} [+] Installing Feroxbuster ${reset}"
 wget https://github.com/epi052/feroxbuster/releases/download/v1.5.2/x86_64-linux-feroxbuster.zip -P ~/Desktop/tools/feroxbuster
 unzip ~/Desktop/tools/feroxbuster/x86_64-linux-feroxbuster.zip -d ~/go/bin/
 chmod 777 ~/go/bin/feroxbuster
 echo "${magenta} [+] Running Feroxbuster for content discovery${reset}"
 for url in $(cat /root/recon/bitdefender.com/subdomain/good/active_subdomain.txt);do
 reg=$(echo $url | sed -e 's;https\?://;;' | sed -e 's;/.*$;;')
 feroxbuster --url $url -w /root/wordlist/mrco24-wordlist/'Critical word big.txt' -x php asp aspx jsp py txt conf config bak backup swp old db zip sql --depth 3 --threads 300 --filter-status 401,403,405,404  --output /root/recon/$domain/Content_Discovery/content_discovery_result.txt
done
fi

echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"
echo " "
echo "${blue} [+] Succesfully saved as content_discovery_result.txt ${reset}"
echo " "
echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"
echo " "
echo "${magenta} [+] Sorting According to Status Codes ${reset}"
cat  /root/recon/$domain/Content_Discovery/content_discovery_result.txt | grep 200 | awk '{print $2}' > /root/recon/$domain/Content_Discovery/status_code_200.txt  
cat  /root/recon/$domain/Content_Discovery/content_discovery_result.txt | grep 204 | awk '{print $2}' > /root/recon/$domain/Content_Discovery/status_code_204.txt
cat  /root/recon/$domain/Content_Discovery/content_discovery_result.txt | grep 301 | awk '{print $2}' > /root/recon/$domain/Content_Discovery/status_code_301.txt
cat  /root/recon/$domain/Content_Discovery/content_discovery_result.txt | grep 302 | awk '{print $2}' > /root/recon/$domain/Content_Discovery/status_code_302.txt
cat  /root/recon/$domain/Content_Discovery/content_discovery_result.txt | grep 307 | awk '{print $2}' > /root/recon/$domain/Content_Discovery/status_code_307.txt
cat  /root/recon/$domain/Content_Discovery/content_discovery_result.txt | grep 308 | awk '{print $2}' > /root/recon/$domain/Content_Discovery/status_code_308.txt
cat  /root/recon/$domain/Content_Discovery/content_discovery_result.txt | grep 401 | awk '{print $2}' > /root/recon/$domain/Content_Discovery/status_code_401.txt
cat  /root/recon/$domain/Content_Discovery/content_discovery_result.txt | grep 403 | awk '{print $2}' >  /root/recon/$domain/Content_Discovery/status_code_403.txt
cat  /root/recon/$domain/Content_Discovery/content_discovery_result.txt | grep 405 | awk '{print $2}' >  /root/recon/$domain/Content_Discovery/status_code_405.txt
echo " "
echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"

echo " "
echo "${blue} [+] Succesfully saved the results according to their status codes ${reset}"
echo " "
echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"

for domain in $(cat $host);
do
#dirsearch -l /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  -w /root/recon/$domain/url/url_endpoints.txt -i 200,301,302 | tee -a /root/recon/$domain/dri/Endpoint_Dir.txt
ffuf -u https://HFUZZ/WFUZZ -w /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt:HFUZZ -w /root/recon/$domain/url/url_endpoints.txt:WFUZZ -ac -fs 0 -v -mc 200,301,302,401,403  | grep "| URL |" | awk '{print $4}' | sed 's/^http[s]:\/\///g' | sort -u | grep $domain | tee -a /root/recon/$domain/dri/fuffEndpoint_Dir.txt
#ffuf -u https://HFUZZ/WFUZZ -w active_subdomain.txt:HFUZZ -w /root/wordlist/SecLists/Discovery/Web-Content/raft-large-directories.txt:WFUZZ -mc 200,301,302,401,403
done
}

for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  | dnsx -a -resp-only | tee -a /root/recon/$domain/subdomain/good/final/subdomain_ip.txt
dirsearch -l /root/recon/$domain/subdomain/good/final/subdomain_ip.txt -e php,asp,aspx,jsp,py,txt,conf,config,bak,backup,swp,old,db,sqlasp,asp~,aspx~,py~,rb,rb~,php~,bkp,cgi,cache,csv,html,inc,jar,js,json,jsp~,lock,log,rar,sql,sql.gz,sql.zip,sql.rar,sql.tar.gz,sql~,swp~,tar,tar.bz2,wadl,zip -i 200 –full-url | tee -a /root/recon/$domain/dri/sub_ip_dri_activ.txt
done
}
ip_sub

