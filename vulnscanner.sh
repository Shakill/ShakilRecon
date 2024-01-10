#!/bin/bash

host=$1
wordlist="/root/wordlist/SecLists/Discovery/DNS/dns-Jhaddix.txt"
resolver="/root/wordlist/resolvers.txt"


#Logo
logo(){
echo "                                                                             "
echo "                                                                             "
echo "                                                                             "
echo "============================================================================="
echo "        _   __         __         ____                                       "
echo "       | | / / __ __  / /  ___   / __/ ____ ___ _  ___   ___  ___   ____     "
echo "       | |/ / / // / / /  / _ \ _\ \  / __// _  / / _ \ / _ \/ -_) / __/     "
echo "       |___/  \___/ /_/  /_//_//___/  \__/ \__/ /_//_//_//_/\__/ /_/         "                                                         
echo "                                                                             "
echo "                                                              by @Shakil     "
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



vuln_scanner(){
for domain in $(cat $host);
do
#mkdir -p /root/recon/$domain/subdomain /root/recon/$domain/subdomain/good /root/recon/$domain/subdomain/good/final /root/recon/$domain/subdomain/good/final/best /root/recon/$domain/Subdomain-Takeover /root/recon/$domain/Subdomain-Screenshots /root/recon/$domain/Special_subdomain /root/recon/$domain/Special_subdomain/scan /root/recon/$domain/scan  /root/recon/$domain/scan/my-jaeles /root/recon/$domain/scan/jaeles /root/recon/$domain/scan/jaeles/my-url /root/recon/$domain/scan/jaeles/url /root/recon/$domain/dri  /root/recon/$domain/scan/nuclei/Php-My-Admin /root/recon/$domain/scan/nuclei /root/recon/$domain/scan/new-nuclei /root/recon/$domain/url /root/recon/$domain/url/endpoint /root/recon/$domain/Secret-api /root/recon/$domain/gf /root/recon/$domain/xss /root/recon/$domain/sql /root/recon/$domain/js_url /root/recon/$domain/git_dork /root/recon/$domain/SQL

nuclei -l /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  -t /root/nuclei-templates/http/ -c 50 -o /root/recon/$domain/scan/new-nuclei/All.txt -v
jaeles scan -c 50 -s /root/templates/ghsec-jaeles-signatures -U /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  -o /root/recon/$domain/scan/jaeles/ghsec_signatures.txt -v
nuclei -l /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  -t /root/my-templates/Templates/cves/ -c 50 -o /root/recon/$domain/scan/new-nuclei/cves.txt -v
jaeles scan -c 50 -s /root/templates/jaeles-signatures -U /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  -o /root/recon/$domain/scan/jaeles/jaeles_signatures.txt -v
nuclei -l /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  -t /root/my-templates/Templates/Vulnerability-Templates/ -c 50 -o /root/recon/$domain/scan/new-nuclei/Vuln_templates.txt -v
done
}
vuln_scanner
<<COMMENT
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
paramspider -l /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt -s
#cat /root/OK-VPS/tools/paramspider/results/*.txt > /root/OK-VPS/tools/paramspider/results/ParamSpider_all.txt && cp -r /root/OK-VPS/tools/paramspider/results/ParamSpider_all.txt /root/recon/$domain/url 
#mv /root/recon/output.txt /root/recon/$domain/url/output.txt
cat /root/recon/results/*.txt > /root/recon/$domain/url/params.txt
cp /root/recon/web_archive_urls.sh /root/recon/$domain/url/
cd /root/recon/$domain/url && ./web_archive_urls.sh /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt 
cat /root/recon/$domain/url/*.txt | sort --unique | grep $domain | tee /root/recon/$domain/url/sort-url.txt
httpx -l /root/recon/$domain/url/sort-url.txt -o /root/recon/$domain/url/url_httpx.txt
arjun -i /root/recon/$domain/url/url_httpx.txt -t 20 -oT /root/recon/$domain/url/arjun.txt
cat /root/recon/$domain/url/*.txt | tee -a /root/recon/$domain/url/2all-url.txt
cat /root/recon/$domain/url/2all-url.txt | sort --unique | tee /root/recon/$domain/url/final-url.txt
cat /root/recon/$domain/url/final-url.txt | egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpep|\.svg|\.css|\.ico" | sed 's/:88//9;s/:443//g' | sort -u | tee -a /root/recon/$domain/url/valid_urls.txt

done
}
find_urls
COMMENT


