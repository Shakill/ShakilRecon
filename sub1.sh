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
github-subdomains -t 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 -d $domain -o /root/recon/$domain/subdomain/github_sub.txt
#Install v3.23.3 amass
amass enum -passive -norecursive -noalts -d $domain -o /root/recon/$domain/subdomain/amass_sub_passive.txt
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


httpx_resolver(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/final/http_domain_for_brut.txt | analyticsrelationships | awk '{print $2}' | grep $domain | sort -u | tee -a /root/recon/$domain/subdomain/good/final/analyticsrelationships_sub.txt
cat /root/recon/$domain/subdomain/good/final/*.txt | httpx | sort --unique | tee -a /root/recon/$domain/subdomain/good/final/best/king_httpx_sub.txt
cat /root/recon/$domain/subdomain/good/final/best/king_httpx_sub.txt | sed -e 's_https*://__' | sed -e 's_www.__'| sort --unique | tee -a /root/recon/$domain/subdomain/good/final/best/sub_brutforce_file.txt 
#......................................................................
rm /root/recon/$domain/subdomain/good/final/*.txt
done
}
httpx_resolver

sub_brutforce(){
for domain in $(cat $host);
do

cat /root/recon/$domain/subdomain/good/final/best/sub_brutforce_file.txt | dnsgen - | puredns resolve --resolvers /root/wordlist/resolvers.txt | tee -a /root/recon/$domain/subdomain/good/final/best/dnsgen_puredns_sub_2.txt
done
}
sub_brutforce

recursive(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/final/best/*.txt | sort --unique | httpx | sort --unique | tee -a /root/recon/$domain/subdomain/good/final/best/subdomain_for_recursion_httpx.txt
cat /root/recon/$domain/subdomain/good/final/best/subdomain_for_recursion_httpx.txt | sed -e 's_https*://__' | sed -e 's_www.__'| sort --unique | tee -a /root/recon/$domain/subdomain/good/final/best/subdomain_for_recursion.txt
subfinder -all -dL /root/recon/$domain/subdomain/good/final/best/subdomain_for_recursion.txt -o /root/recon/$domain/subdomain/good/final/best/subfinder_recursive.txt
#amass enum -df /root/recon/$domain/subdomain/good/final/best/subdomain_for_recursion.txt -config /root/config.yaml | awk '{print $1}' | grep $domain | sort -u | tee -a /root/recon/$domain/subdomain/good/final/best/amass_recursive.txt
amass enum -passive -norecursive -noalts -df /root/recon/$domain/subdomain/good/final/best/subdomain_for_recursion.txt -o /root/recon/$domain/subdomain/good/final/best/amass_recursive.txt
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
#cp /root/recon/web_archive_urls.sh /root/recon/$domain/url/
#cd /root/recon/$domain/url && ./web_archive_urls.sh /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain/url_list?limit=100&page=1" | grep -o '"url": *"[^"]*"' | grep -o '"[^"]*"$' | tr -d '"' | tee -a /root/recon/$domain/url/alienvault.txt
cat /root/recon/$domain/url/*.txt | sort --unique | grep $domain | tee /root/recon/$domain/url/sort-url.txt
httpx -l /root/recon/$domain/url/sort-url.txt -o /root/recon/$domain/url/url_httpx.txt
arjun -i /root/recon/$domain/url/url_httpx.txt -t 20 -oT /root/recon/$domain/url/arjun.txt
cat /root/recon/$domain/url/*.txt | tee -a /root/recon/$domain/url/2all-url.txt
cat /root/recon/$domain/url/2all-url.txt | httpx | sort --unique | tee /root/recon/$domain/url/final-url.txt
cat /root/recon/$domain/url/final-url.txt | egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpep|\.svg|\.css|\.ico" | sed 's/:88//9;s/:443//g'| grep $domain | sort -u | tee -a /root/recon/$domain/url/valid_urls.txt

done
}
find_urls