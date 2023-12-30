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

#Uncover tool for finding Origin IP
#uncover -q $domain -e shodan,censys,fofa,quake,zoomeye,netlas,criminalip,hunterhow,hunter,shodan-idb | httpx | tee /root/recon/$domain/subdomain/good/uncover_ips.txt

subfinder -all -d $domain -o /root/recon/$domain/subdomain/subfinder.txt
assetfinder -subs-only $domain | tee /root/recon/$domain/subdomain/assetfinder.txt 
#echo  $domain | haktrails subdomains | sed -e 's_https*://__' | sed -e 's_www.__' | tee -a /root/recon/$domain/subdomain/haktrails.txt
findomain -t $domain | tee /root/recon/$domain/subdomain/findomain.txt
#https://kaeferjaeger.gay/?dir=sni-ip-ranges
cat /root/domains_cloud/*.txt | grep $domain | grep -oP "(?<=\[).*(?=\])" | tr ' ' '\n' | sed 's/^*.//' | grep $domain | sort -u | tee -a /root/recon/$domain/subdomain/domains_cloud.txt
#bbot -t $domain -f subdomain-enum
#cp /root/.bbot/scans/insolent_jerry/subdomains.txt /root/recon/$domain/subdomain/bbot.txt
#tugarecon
python3 /root/tugarecon/tugarecon.py -d $domain | awk '{print $3}' |grep -v '@'| grep $domain | sed 's/^\./ /'| sort -u | tee -a /root/recon/$domain/subdomain/tuga.txt
#cp /root/tugarecon/results/$domain/2023-10-17/subdomains.txt /root/recon/$domain/subdomain/tuga.txt
github-subdomains -t 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 -d $domain -o /root/recon/$domain/subdomain/github_sub.txt
#sudomy -d $domain -o /root/recon/$domain/subdomain/sudomy.txt
#should install v4 amass
#amass enum -d $domain -config /root/config.yaml| awk '{print $1}' | grep $domain | sort -u | tee -a /root/recon/$domain/subdomain/amass_sub_passive.txt
#export CENSYS_API_ID=303b2554-31b0-4e2d-a036-c869f23bfb76
#export CENSYS_API_SECRET=sB8T2K8en7LW6GHOkKPOfEDVpdmaDj6t
#python3 /root/OK-VPS/tools/censys-subdomain-finder/censys-subdomain-finder.py $domain -o /root/recon/$domain/subdomain/censys_subdomain.txt
export CHAOS_KEY=8153077428be89cccb4f3f7e20f45a166c0f5565d9cb118b7c529a5d9ee5bd00
chaos -d $domain -o /root/recon/$domain/subdomain/chaos_sub.txt
cero $domain | sed 's/^*.//' | grep -e "\." | sort -u | tee -a /root/recon/$domain/subdomain/cero_ssl_sub.txt
gau --subs $domain --threads 5 |  unfurl -u domains | grep $domain | sort -u -o /root/recon/$domain/subdomain/gau_subdomain.txt
waybackurls $domain |  unfurl -u domains | sort -u -o /root/recon/$domain/subdomain/waybackurl_subdomain.txt
curl --insecure --silent "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | sed "/@/d" | sed -e 's/\.$//' | sort -u | tee /root/recon/$domain/subdomain/web.archive.txt
curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | tee /root/recon/$domain/subdomain/crtsub.txt
curl -s "https://jldc.me/anubis/subdomains/$domain" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee /root/recon/$domain/subdomain/jldcsub.txt
sed -ne 's/^\( *\)Subject:/\1/p;/X509v3 Subject Alternative Name/{
N;s/^.*\n//;:a;s/^\( *\)\(.*\), /\1\2\n\1/;ta;p;q; }' < <(
openssl x509 -noout -text -in <(
openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' \
-connect $domain:443 ) ) | grep -Po '((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+' | sed 's/^\./ /' |  tee /root/recon/$domain/subdomain/altnamesub.txt
#shuffledns -d $domain -w $wordlist -r /root/wordlist/resolvers.txt -o /root/recon/$domain/subdomain/shuffledns.txt
#ffuf -u http://HFUZZ -H "Host: FUZZ.HFUZZ" -w /root/recon/input.txt:HFUZZ -w /root/wordlist/SecLists/Discovery/DNS/dns-Jhaddix.txt:FUZZ -fs 0 -v  | grep "| URL |" | awk '{print $4}' | sed 's/^http[s]:\/\///g' | sort -u | grep $domain | tee -a /root/recon/$domain/subdomain/ffuf.txt
curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" |  sed 's/,.*//' | sort -u | tee -a /root/recon/$domain/subdomain/hackertarget.txt
curl -s "https://rapiddns.io/subdomain/$domain?full=1&down=1" | grep $domain | grep -Po '>\K[^<]*' | sed 's/\.$//' | tee -a /root/recon/$domain/subdomain/rapiddns.txt
anubis -t $domain | grep $domain | tee -a /root/recon/$domain/subdomain/anubis.txt
curl -s "https://subdomainfinder.c99.nl/scans/$(date +"%Y-%m-%d")/$domain" -A "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:59.0)" | grep -Po '.*?//\K.*?(?=/)'  | awk -F "'" '{print $1}' | anew  | grep $domain | tee -a /root/recon/$domain/subdomain/c99_subdomainfinder.txt
cat /root/recon/$domain/subdomain/*.txt | sort --unique | grep $domain | sed 's/^*.//' | tee -a /root/recon/$domain/subdomain/all_sort_sub.txt

done
}
domain_enum


resolving_domains(){
for domain in $(cat $host);
do

httpx -l /root/recon/$domain/subdomain/all_sort_sub.txt -threads 50 -o /root/recon/$domain/subdomain/good/passive_resolving_live_sub_edit.txt
cat /root/recon/$domain/subdomain/good/passive_resolving_live_sub_edit.txt | sed -e 's_https*://__' | sed -e 's_www.__' | sort -u | tee -a /root/recon/$domain/subdomain/good/final/http_domain_for_brut.txt
rm /root/recon/$domain/subdomain/good/passive_resolving_live_sub_edit.txt
done
}
resolving_domains

sub_brutforce(){
for domain in $(cat $host);
do

#............................................................................................................
#If Gotator not to run
#mv /root/recon/$domain/subdomain/good/passive_resolving_live_sub.txt /root/recon/$domain/subdomain/good/final/http_domain_for_brut.txt
#..........................................................................................................
#puredns bruteforce /root/wordlist/SecLists/Discovery/DNS/dns-Jhaddix.txt -d /root/recon/$domain/subdomain/good/final/http_domain_for_brut.txt -r /root/wordlist/resolvers.txt | tee -a /root/recon/$domain/subdomain/good/final/purdns_sub.txt
cat /root/recon/$domain/subdomain/good/final/http_domain_for_brut.txt | dnsgen - | puredns resolve --resolvers /root/wordlist/resolvers.txt | tee -a /root/recon/$domain/subdomain/good/final/dnsgen_purdns_sub.txt
done
}
sub_brutforce

httpx_resolver(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/final/http_domain_for_brut.txt | analyticsrelationships | awk '{print $2}' | grep $domain | sort -u | tee -a /root/recon/$domain/subdomain/good/final/analyticsrelationships_sub.txt
cat /root/recon/$domain/subdomain/good/final/*.txt | httpx | sort --unique | tee -a /root/recon/$domain/subdomain/good/final/best/king_httpx_sub.txt
cat /root/recon/$domain/subdomain/good/final/best/king_httpx_sub.txt | sed -e 's_https*://__' | sed -e 's_www.__'| sort --unique | tee -a /root/recon/$domain/subdomain/good/final/best/sub_brutforce_2_file.txt 
#......................................................................
rm /root/recon/$domain/subdomain/good/final/*.txt
done
}
httpx_resolver
wordlist_Making(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/final/best/sub_brutforce_2_file.txt | tok | anew | tee -a  /root/wordlist/my_wordlist.txt
done
}
wordlist_Making

sub_brutforce_2(){
for domain in $(cat $host);
do
puredns bruteforce /root/wordlist/my_wordlist.txt -d /root/recon/$domain/subdomain/good/final/best/sub_brutforce_2_file.txt -r /root/wordlist/resolvers.txt | tee -a /root/recon/$domain/subdomain/good/final/best/puredns_sub_by_my_wordlist.txt
cat /root/recon/$domain/subdomain/good/final/best/sub_brutforche_2_file.txt | dnsgen - | puredns resolve --resolvers /root/wordlist/resolvers.txt | tee -a /root/recon/$domain/subdomain/good/final/best/dnsgen_puredns_sub_2.txt
done
}
sub_brutforce_2

recursive(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/final/best/*.txt | sort --unique | httpx | sort --unique | tee -a /root/recon/$domain/subdomain/good/final/best/subdomain_for_recursion_httpx.txt
cat /root/recon/$domain/subdomain/good/final/best/subdomain_for_recursion_httpx.txt | sed -e 's_https*://__' | sed -e 's_www.__'| sort --unique | tee -a /root/recon/$domain/subdomain/good/final/best/subdomain_for_recursion.txt
subfinder -all -dL /root/recon/$domain/subdomain/good/final/best/subdomain_for_recursion.txt -o /root/recon/$domain/subdomain/good/final/best/subfinder_recursive.txt
#amass enum -df /root/recon/$domain/subdomain/good/final/best/subdomain_for_recursion.txt -config /root/config.yaml | awk '{print $1}' | grep $domain | sort -u | tee -a /root/recon/$domain/subdomain/good/final/best/amass_recursive.txt
done
}
recursive



httpx_resolve_2(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/final/best/*.txt | sort --unique | grep $domain | httpx | sort --unique | tee -a /root/recon/$domain/subdomain/good/final/all_active_sub.txt
#...........................................
rm /root/recon/$domain/subdomain/good/final/best/*.txt
mv /root/recon/$domain/subdomain/good/final/all_active_sub.txt /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt
rm /root/recon/$domain/subdomain/good/final/all_active_sub.txt
#...................................................
done
}
httpx_resolve_2
COMMENT

interesting_subs(){
for domain in $(cat $host);
do
gf interestingsubs /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  | tee /root/recon/$domain/subdomain/good/final/best/interestingsubs.txt 
done
}
interesting_subs

nrich_cve(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  | dnsx -a -resp-only | nrich -  | tee -a /root/recon/$domain/scan/nrich_cve.txt 
done
}
nrich_cve 

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
unimap --fast-scan --file /root/recon/$domain/subdomain/good/final/best/all_active_sub_for_naabu.txt --ports "81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672" | tee -a /root/recon/$domain/scan/open_port_unimap.txt

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

find_urls(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  |  gauplus -t 30 | tee -a /root/recon/$domain/url/gaplus-urls.txt
cat /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  | waybackurls | tee /root/recon/$domain/url/waybackurls.txt
cat /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  | hakrawler | tee -a /root/recon/$domain/url/hakrawler-urls.txt
gospider -S /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  -c 10 -d 1 --other-source | grep -o 'https\?://[^ ]\+' > /root/recon/$domain/url/gospider-url.txt
cat /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  | katana -o /root/recon/$domain/url/katana.txt
#cat /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  | xargs -n 1 -I {} python3 /root/OK-VPS/tools/ParamSpider/paramspider.py --domain {} --level high  | grep -o 'https\?://[^ ]\+' > /root/recon/$domain/url/all_spiderparamters.txt

#waymore
python3 /root/waymore/waymore.py -i $domain -mode U | sort -u | tee -a /root/recon/$domain/url/waymore.txt
#xnLinkFinder
python3 /root/xnLinkFinder/xnLinkFinder.py -i $domain -sf $domain -d 2 -v | sed -e 's_https*://__' | sed -e 's_www.__' | grep $domain | sort --unique | httpx | tee -a /root/recon/$domain/url/xlinkfinder.txt
#cat /root/recon/$domain/subdomain/good/final/active_subdomain.txt  | xargs -n 1 -I {} python3 /root/OK-VPS/tools/ParamSpider/paramspider.py --domain {} --level high  | grep -o 'https\?://[^ ]\+' > /root/recon/$domain/url/all_spiderparamters.txt
#paramspider -l /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt -s
#cat /root/OK-VPS/tools/paramspider/results/*.txt > /root/OK-VPS/tools/paramspider/results/ParamSpider_all.txt && cp -r /root/OK-VPS/tools/paramspider/results/ParamSpider_all.txt /root/recon/$domain/url 
#mv /root/recon/output.txt /root/recon/$domain/url/output.txt
#cat /root/recon/results/*.txt > /root/recon/$domain/url/params.txt
cp /root/recon/web_archive_urls.sh /root/recon/$domain/url/
cd /root/recon/$domain/url && ./web_archive_urls.sh /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain/url_list?limit=100&page=1" | grep -o '"url": *"[^"]*"' | grep -o '"[^"]*"$' | tr -d '"' | tee -a /root/recon/$domain/url/alienvault.txt
cat /root/recon/$domain/url/*.txt | sort --unique | grep $domain | tee /root/recon/$domain/url/sort-url.txt
httpx -l /root/recon/$domain/url/sort-url.txt -o /root/recon/$domain/url/url_httpx.txt
arjun -i /root/recon/$domain/url/url_httpx.txt -t 20 -oT /root/recon/$domain/url/arjun.txt
cat /root/recon/$domain/url/*.txt | tee -a /root/recon/$domain/url/2all-url.txt
cat /root/recon/$domain/url/2all-url.txt | httpx | sort --unique | tee /root/recon/$domain/url/final-url.txt
cat /root/recon/$domain/url/final-url.txt | egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpep|\.svg|\.css" | sed 's/:88//9;s/:443//g'| grep $domain | sort -u | tee -a /root/recon/$domain/url/valid_urls.txt

done
}
find_urls
