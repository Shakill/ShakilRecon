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

nuclei -l /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  -t /root/nuclei-templates/ -c 50 -o /root/recon/$domain/scan/new-nuclei/All.txt -v
jaeles scan -c 50 -s /root/templates/ghsec-jaeles-signatures -U /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  -o /root/recon/$domain/scan/my-jaeles/ -v
nuclei -l /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  -t /root/my-templates/Templates/cves/ -c 50 -o /root/recon/$domain/scan/new-nuclei/cves.txt -v
jaeles scan -c 50 -s /root/templates/jaeles-signatures -U /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  -o /root/recon/$domain/scan/jaeles/ -v
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

Url_endpoints(){
for domain in $(cat $host);
do
cat /root/recon/$domain/url/final-url.txt | cut -d "/" -f4- >> /root/recon/$domain/url/endpoint/urlcutting_endpoints.txt
echo $domain | gau | wordlistgen | sort -u | tee -a /root/recon/$domain/url/endpoint/gau_wordlistgen.txt
mv /root/recon/parameters.txt /root/recon/$domain/url/endpoint/xnlinkfinder.txt
mv /root/recon/output.txt /root/recon/$domain/url/endpoint/endpoint_xnlinkfinder.txt
cat /root/recon/$domain/url/endpoint/*.txt | sort -u | tee -a /root/recon/$domain/url/endpoint/url_endpoints.txt

#............................
mv /root/recon/$domain/url/valid_urls.txt /root/recon/$domain/url/endpoint/valid_urls.txt
rm /root/recon/$domain/url/*.txt
mv /root/recon/$domain/url/endpoint/valid_urls.txt /root/recon/$domain/url/valid_urls.txt
mv /root/recon/$domain/url/endpoint/url_endpoints.txt /root/recon/$domain/url/url_endpoints.txt
rm /root/recon/$domain/url/endpoint/*.txt
#.....................
done
}
Url_endpoints


gf_patterns(){
for domain in $(cat $host);
do
gf xss /root/recon/$domain/url/valid_urls.txt | tee /root/recon/$domain/gf/xss.txt
gf my-lfi /root/recon/$domain/url/valid_urls.txt | tee /root/recon/$domain/gf/my-lfi.txt
gf sqli /root/recon/$domain/url/valid_urls.txt | tee /root/recon/$domain/gf/sqli.txt
gf lfi /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/lfi.txt
gf redirect /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/my-Redirect.txt
gf aws-keys /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/aws-keys-json.txt
#gf interestingsubs /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt |  tee /root/recon/$domain/gf/interestingsubs.txt
gf s3-buckets /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/s3-buckets.txt
gf servers /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/servers.txt
gf debug-pages /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/debug-pages.txt
gf debug_logic /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/debug_logic.txt
gf img-traversal /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/img-traversal.txt
gf php-sources /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/php-sources.txt
gf upload-fields /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/upload-fields.txt
gf php-errors /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/php-errors.txt
gf http-auth /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/http-auth.txt
gf idor /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/idor.txt
gf interestingparams /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/interestingparams.txt
gf interestingEXT /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/interestingEXT.txt
gf rce /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/rce.txt
#gf xml /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/xml.txt
#gf ip /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/ip.txt
gf ssrf /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/ssrf.txt
gf ssti /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/ssti.txt
#gf parsers /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/parsers.txt
#gf jwt /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/jwt.txt
gf cors /root/recon/$domain/url/valid_urls.txt |  tee /root/recon/$domain/gf/cors.txt
done
}
gf_patterns

SQL(){
for domain in $(cat $host);
do

cat /root/recon/$domain/url/valid_urls.txt | grep ".php" | sed 's/\.php.*/.php\//' | sort -u | sed 's/$/%27%22%60/' | while read url do ; do curl --silent "$url" | grep -qs "You have an error in your SQL syntax" && echo -e "$url \e[1;32mVulnerable\e[0m" || echo -e "$url \e[1;31mNot Vulnerable\e[0m" ;done | tee -a /root/recon/$domain/sql/curl_SQL_ERROR.txt
#sqlmap -m /root/recon/$domain/url/valid_urls.txt --level 5 --batch --risk 3  --random-agent | tee -a /root/recon/$domain/sql/sqlmap_sql_url.txt
ghauri -r /root/recon/$domain/url/valid_urls.txt --level=3 --banner --dbs | tee -a /root/recon/$domain/sql/ghauri_sql_url.txt
python3 /root/HBSQLI/hbsqli.py -l /root/recon/$domain/url/valid_urls.txt -p /root/HBSQLI/payloads.txt -H /root/HBSQLI/headers.txt -v | tee -a /root/recon/$domain/sql/hbsqli_url.txt
done
}
SQL


Refactors_xss(){
for domain in $(cat $host);
do

cat /root/recon/$domain/url/valid_urls.txt | urldedupe -qs | bhedak '"><Svg Only=1 OnLoad=confirm(atob("Q2xvdWRmbGFyZSBYU1MgQG1fa2VsZXBjZQ=="))>' | airixss -payload "confirm(1)" | egrep -v 'Not' | tee -a /root/recon/$domain/xss/bhedak_airixss_urldedupe.txt

cat /root/recon/$domain/url/valid_urls.txt | Gxss -o /root/recon/$domain/xss/gxss.txt
cat /root/recon/$domain/url/valid_urls.txt | kxss | tee -a  /root/recon/$domain/xss/kxss_url.txt
cat /root/recon/$domain/xss/kxss_url.txt | sed 's/.*on//' | sed 's/=.*/=/' > /root/recon/$domain/xss/kxss_url_active.txt
cat /root/recon/$domain/xss/kxss_url_active.txt | dalfox pipe | tee /root/recon/$domain/xss/kxss_dalfoxss.txt
cat /root/recon/$domain/xss/gxss.txt | dalfox pipe | tee /root/recon/$domain/xss/gxss_dalfoxss.txt
cat /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  | /root/OK-VPS/tools/findom-xss/./findom-xss.sh
done
}
Refactors_xss

xss_vibes(){
for domain in $(cat $host);
do
python3 /root/xss_vibes/main.py -f /root/recon/$domain/url/valid_urls.txt -t  -o /root/recon/$domain/xss/xss_vibes.txt
done
}
xss_vibes

Dom_xss(){
for domain in $(cat $host);
do
cat /root/recon/$domain/url/valid_urls.txt | /root/OK-VPS/tools/findom-xss/./findom-xss.sh | tee -a /root/recon/$domain/xss/Dom_xss.txt
done
}
Dom_xss

Open_redirect(){
for domain in $(cat $host);
do
cat /root/recon/$domain/url/valid_urls.txt | grep -a -i \=http | bhedak 'http://evil.com' | while read host do;do curl -s -L $host -I | grep "evil.com" && echo -e "$host \033[0;31mVulnerable\n" ;done | tee /root/recon/$domain/OpenRedirect/openredirect.txt
done
}
Open_redirect
<<COMMENT
Fuzz_Endpoint(){
for domain in $(cat $host);
do
#dirsearch -l /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  -w /root/recon/$domain/url/url_endpoints.txt -i 200,301,302 | tee -a /root/recon/$domain/dri/Endpoint_Dir.txt
ffuf -u https://HFUZZ/WFUZZ -w /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt:HFUZZ -w /root/recon/$domain/url/url_endpoints.txt:WFUZZ -ac -fs 0 -v -mc 200,301,302,401,403  | grep "| URL |" | awk '{print $4}' | sed 's/^http[s]:\/\///g' | sort -u | grep $domain | tee -a /root/recon/$domain/dri/fuffEndpoint_Dir.txt
#ffuf -u https://HFUZZ/WFUZZ -w active_subdomain.txt:HFUZZ -w /root/wordlist/SecLists/Discovery/Web-Content/raft-large-directories.txt:WFUZZ -mc 200,301,302,401,403
done
}
Fuzz_Endpoint
COMMENT
<<COMMENT
FUZZ_active(){
for domain in $(cat $host);
do
dirsearch -l /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  | tee -a /root/recon/$domain/dri/dri_activ.txt
done
}
FUZZ_active
COMMENT
<<COMMENT
ip_sub(){
for domain in $(cat $host);
do
cat /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  | dnsx -a -resp-only | tee -a /root/recon/$domain/subdomain/good/final/subdomain_ip.txt
dirsearch -l /root/recon/$domain/subdomain/good/final/subdomain_ip.txt -e php,asp,aspx,jsp,py,txt,conf,config,bak,backup,swp,old,db,sqlasp,asp~,aspx~,py~,rb,rb~,php~,bkp,cgi,cache,csv,html,inc,jar,js,json,jsp~,lock,log,rar,sql,sql.gz,sql.zip,sql.rar,sql.tar.gz,sql~,swp~,tar,tar.bz2,wadl,zip -i 200 –full-url | tee -a /root/recon/$domain/dri/sub_ip_dri_activ.txt
done
}
ip_sub
COMMENT
Get_js(){
for domain in $(cat $host);
do
cat /root/recon/$domain/url/valid_urls.txt | getJS --complete | grep $domain | tee /root/recon/$domain/js_url/getjs_urls.txt
cat /root/recon/$domain/subdomain/good/final/best/all_active_sub.txt  | getJS --complete | grep $domain | tee /root/recon/$domain/js_url/Domain_js_urls.txt
cat /root/recon/$domain/js_url/*.txt > /root/recon/$domain/js_url/all_js_url.txt
cat /root/recon/$domain/js_url/all_js_url.txt | sort --unique | tee /root/recon/$domain/js_url/final_js_url.txt
cat /root/recon/$domain/js_url/final_js_url.txt | httpx -threads 150 -o /root/recon/$domain/js_url/jshttpxurl.txt
cat /root/recon/$domain/js_url/jshttpxurl.txt | sort --unique | tee /root/recon/$domain/url/good_js_url.txt
rm /root/recon/$domain/js_url/*.txt
mv /root/recon/$domain/url/good_js_url.txt /root/recon/$domain/js_url/good_js_url.txt
/root/OK-VPS/tools/JSScanner/./script.sh /root/recon/$domain/js_url/good_js_url.txt
nuclei -t /root/nuclei-templates/http/exposures/ -l /root/recon/$domain/js_url/good_js_url.txt -c 50 -o /root/recon/$domain/js_url/exposed_js.txt

#relative-url-extractor https://github.com/jobertabma/relative-url-extractor
#LinkFinder https://github.com/GerbenJavado/LinkFinder
#Arjun https://github.com/s0md3v/Arjun
done
}
Get_js
