#!/bin/bash

host=$1
wordlist="/root/wordlist/SecLists/Discovery/DNS/dns-Jhaddix.txt"
resolver="/root/wordlist/resolvers.txt"



logo(){
echo "                                                                             "
echo "                                                                             "
echo "                                                                             "
echo "============================================================================="
echo "                                                                             "
echo "  ____    _               _      _   _   ____                                "
echo " / ___|  | |__     __ _  | | __ (_) | | |  _ \    ___    ___    ___    _ __  "
echo " \___ \  |  _ \   / _  | | |/ / | | | | | |_) |  / _ \  / __|  / _ \  |  _ \ "
echo "  ___) | | | | | | (_| | |   <  | | | | |  _ <  |  __/ | (__  | (_) | | | | |"
echo " |____/  |_| |_|  \__,_| |_|\_\ |_| |_| |_| \_\  \___|  \___|  \___/  |_| |_|"
echo "                                                                             "
echo "                                                                   by @Shakil"
echo "============================================================================="
echo "                                                                             "
echo "                                                                             "
echo "                                                                             "
}
logo




Api_export(){
for domain in $(cat $host);
do
export SHODAN_API_KEY=pHHlgpFt8Ka3Stb5UlTxcaEwciOeF2QM
export CENSYS_API_ID=303b2554-31b0-4e2d-a036-c869f23bfb76
export CENSYS_API_SECRET=sB8T2K8en7LW6GHOkKPOfEDVpdmaDj6t
export FOFA_EMAIL=m.shakil.bd11@gmail.com
export FOFA_KEY=a20ee4c7c14c552819154851608af12a
export QUAKE_TOKEN=aca8654f-bf18-4854-9222-0b34d6034b23
export HUNTER_API_KEY=d5c098ebf25c45274ac32c81e3dda94a8c46059a
export ZOOMEYE_API_KEY=409Ff566-1214-89025-7E0F-cc2c4a14e82
export NETLAS_API_KEY=5ZnQ0iQ9KEIv8tjEtiHxtm6UdCYQjKPS
export CRIMINALIP_API_KEY=D6K6CAszmXvwCxhruZ40lv0klE5WxsqnvYxrFZFYRXHah5IYPPnmTT3nkKxJ
export PUBLICWWW_API_KEY=a1cbd16b31a1807330b8e372b7243a47
export HUNTERHOW_API_KEY=af9ed1d3ab962ffff47cd42e0f870cbd0ec2e1ac5cb5270f08908fae7956a6c5
export GITHUB_TOKEN=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
export CHAOS_KEY=8153077428be89cccb4f3f7e20f45a166c0f5565d9cb118b7c529a5d9ee5bd00
shodan init pHHlgpFt8Ka3Stb5UlTxcaEwciOeF2QM 
done
}



domain_enum(){
for domain in $(cat $host);
do
mkdir -p /root/recon/$domain/subdomain /root/recon/$domain/subdomain/good /root/recon/$domain/subdomain/good/final /root/recon/$domain/subdomain/good/final/best /root/recon/$domain/Subdomain-Takeover /root/recon/$domain/Subdomain-Screenshots /root/recon/$domain/Special_subdomain /root/recon/$domain/Special_subdomain/scan /root/recon/$domain/scan  /root/recon/$domain/scan/my-jaeles /root/recon/$domain/scan/jaeles /root/recon/$domain/scan/jaeles/my-url /root/recon/$domain/scan/jaeles/url /root/recon/$domain/dri  /root/recon/$domain/scan/nuclei/Php-My-Admin /root/recon/$domain/scan/nuclei /root/recon/$domain/scan/new-nuclei /root/recon/$domain/url /root/recon/$domain/url/endpoint /root/recon/$domain/Secret-api /root/recon/$domain/gf /root/recon/$domain/xss /root/recon/$domain/sql /root/recon/$domain/js_url /root/recon/$domain/git_dork /root/recon/$domain/SQL


subfinder -all -d $domain -o /root/recon/$domain/subdomain/subfinder.txt
cat /root/domains_cloud/*.txt | grep $domain | grep -oP "(?<=\[).*(?=\])" | tr ' ' '\n' | sed 's/^*.//' | grep $domain | sort -u | tee -a /root/recon/$domain/subdomain/domains_cloud.txt
#github-subdomains -t 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  -d $domain -o /root/recon/$domain/subdomain/github_sub.txt
#Install v3.23.3 amass
amass enum -passive -norecursive -noalts -d $domain -o /root/recon/$domain/subdomain/amass_sub_passive.txt
curl -s "https://www.google.com/search?q=site%3A$domain" -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" | grep -Eo "(http|https)://[a-zA-Z0-9._-]+\.$domain" | sed 's/.*\/\///' | sort -u | tee -a /root/recon/$domain/subdomain/google_sub.txt 
curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | tee /root/recon/$domain/subdomain/crtsub.txt
curl -s "https://www.bing.com/search?q=site%3A$domain" -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" | grep -Eo "(http|https)://[a-zA-Z0-9._-]+\.$domain" | sed 's/.*\/\///' | sort -u | tee -a /root/recon/$domain/subdomain/bing_sub.txt 
curl --insecure --silent "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | sed "/@/d" | sed -e 's/\.$//' | sort -u | tee /root/recon/$domain/subdomain/web.archive.txt
curl -s "https://rapiddns.io/subdomain/$domain?full=1&down=1" | grep $domain | grep -Po '>\K[^<]*' | sed 's/\.$//' | tee -a /root/recon/$domain/subdomain/rapiddns.txt
cero $domain | sed 's/^*.//' | grep -e "\." | sort -u | tee -a /root/recon/$domain/subdomain/cero_ssl_sub.txt
cat /root/recon/$domain/subdomain/*.txt | sort --unique | grep $domain | sed 's/^*.//' | tee -a /root/recon/$domain/subdomain/all_sort_sub.txt

done
}
domain_enum


<<COMMENT
wordlist_Making(){
for domain in $(cat $host);
do
mv /root/recon/$domain/subdomain/all_sort_sub.txt /root/recon/$domain/subdomain/good/copy_all_sort_sub.txt
cat /root/recon/$domain/subdomain/good/copy_all_sort_sub.txt | analyticsrelationships | awk '{print $2}' | grep $domain | sort -u | tee -a /root/recon/$domain/subdomain/good/final/best/analyticsrelationships_sub.txt
cat /root/recon/$domain/subdomain/good/*.txt | sed -e 's_https*://__' | sed -e 's_www.__' | tee -a /root/recon/$domain/subdomain/good/final/best/sub_brutforce_file.txt

cat /root/recon/$domain/subdomain/good/final/best/sub_brutforce_file.txt | tok | anew | tee -a  /root/recon/$domain/subdomain/good/final/my_wordlist.txt
done
}
wordlist_Making

sub_brutforce(){
for domain in $(cat $host);
do
puredns bruteforce /root/recon/$domain/subdomain/good/final/my_wordlist.txt -d /root/recon/$domain/subdomain/good/final/best/sub_brutforce_file.txt -r /root/wordlist/resolvers.txt | tee -a /root/recon/$domain/subdomain/good/final/best/puredns_sub_by_my_wordlist.txt
#cat /root/recon/$domain/subdomain/good/final/best/sub_brutforce_file.txt | dnsgen - | puredns resolve --resolvers /root/wordlist/resolvers.txt | tee -a /root/recon/$domain/subdomain/good/final/best/dnsgen_puredns_sub.txt
done
}
sub_brutforce
COMMENT
recursive(){
for domain in $(cat $host);
do
mv /root/recon/$domain/subdomain/all_sort_sub.txt /root/recon/$domain/subdomain/good/final/best/copy_all_sort_sub.txt
cat /root/recon/$domain/subdomain/good/final/best/copy_all_sort_sub.txt | analyticsrelationships | awk '{print $2}' | grep $domain | sort -u | tee -a /root/recon/$domain/subdomain/good/final/best/analyticsrelationships_sub.txt
cat /root/recon/$domain/subdomain/good/final/best/*.txt | sort --unique | tee -a /root/recon/$domain/subdomain/good/final/best/subdomain_for_recursion_httpx.txt
cat /root/recon/$domain/subdomain/good/final/best/subdomain_for_recursion_httpx.txt | sed -e 's_https*://__' | sed -e 's_www.__'| sort --unique | tee -a /root/recon/$domain/subdomain/good/final/best/subdomain_for_recursion.txt
subfinder -all -dL /root/recon/$domain/subdomain/good/final/best/subdomain_for_recursion.txt -o /root/recon/$domain/subdomain/good/final/best/subfinder_recursive.txt
#amass enum -df /root/recon/$domain/subdomain/good/final/best/subdomain_for_recursion.txt -config /root/config.yaml | awk '{print $1}' | grep $domain | sort -u | tee -a /root/recon/$domain/subdomain/good/final/best/amass_recursive.txt
amass enum -passive -norecursive -noalts -df /root/recon/$domain/subdomain/good/final/best/subdomain_for_recursion.txt -o /root/recon/$domain/subdomain/good/final/best/amass_recursive.txt
done
}
recursive



httpx_resolve(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/final/best/*.txt| httpx | grep $domain | tee -a /root/recon/$domain/subdomain/good/final/active_sub.txt
cat /root/recon/$domain/subdomain/good/final/active_sub.txt | sort --unique | tee -a /root/recon/$domain/subdomain/good/final/all_active_sub.txt
#...........................................
rm /root/recon/$domain/subdomain/good/final/best/*.txt
mv /root/recon/$domain/subdomain/good/final/all_active_sub.txt /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt
rm /root/recon/$domain/subdomain/good/final/all_active_sub.txt
#...................................................
done
}
httpx_resolve


interesting_subs(){
for domain in $(cat $host);
do
gf interestingsubs /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  | tee /root/recon/$domain/subdomain/good/final/best/interestingsubs.txt 
done
}
interesting_subs
<<COMMENT
nrich_cve(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  | dnsx -a -resp-only | nrich -  | tee -a /root/recon/$domain/scan/nrich_cve.txt 
done
}
nrich_cve 
COMMENT
Subdomain_takeover(){
for domain in $(cat $host);
do
./cname.sh /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt
subzy run --targets /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  | tee -a /root/recon/$domain/Subdomain-Takeover/subzy_subdomain_takeover.txt
#NtHiM  -f /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  -o /root/recon/$domain/Subdomain-Takeover/NtHiM_subdomain_takeover.txt -v
nuclei -l /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  -t /root/nuclei-templates/http/takeovers/ -c 100 -o /root/recon/$domain/Subdomain-Takeover/nuclei_subdomain_takeover.txt -v
#nuclei -l /root/recon/$domain/subdomain/good/take_ge_subdomain.txt -t /root/templates/my-nuclei-templates/My-Nuclei-Templates/subdomain-takeover/subdomain-takeover_detect-all-takeovers.yaml -c 100 -o /root/recon/$domain/Subdomain-Takeover/poc.txt -v

done
}
Subdomain_takeover


open_port(){
for domain in $(cat $host);
do
#In below line U can use this | sed 's/https\?:\/\///' |
cat /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt | sed -e 's_https*://__' | tee -a /root/recon/$domain/subdomain/good/final/best/all_active_sub_for_naabu.txt
#naabu -list /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  -top-ports 1000 -exclude-ports 80,443,21,22,25 -o /root/recon/$domain/scan/open_port.txt
#naabu -list /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  -p - -exclude-ports 80,443,21,22,25 -o /root/recon/$domain/scan/filter_all_open_port.txt
unimap --fast-scan --file /root/recon/$domain/subdomain/good/final/best/all_active_sub_for_naabu.txt --ports "21,81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672" | tee -a /root/recon/$domain/scan/open_port_unimap.txt

#..........................................................................................
rm /root/recon/$domain/subdomain/good/final/best/all_active_sub_for_naabu.txt

done
}
open_port

#web_Screenshot(){
#for domain in $(cat $host);
#do
#cd /root/recon/$domain/Subomain-Screenshots 
#gowitness file -f /root/recon/$domain/subdomain/good/final/active_subdomain.txt 
#done
#}
#web_Screenshot

CloudFlare_Checker(){
for domain in $(cat $host);
do
cf-check -d /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  | tee -a /root/recon/$domain/subdomain/good/cloudflare_check.txt
done
}
CloudFlare_Checker

