#### 
#
# Template header  
# - Build into Splunk TA-CyberCOVID19 
#  
# Static - Multiiple Lookup files 
#
# Dynamic - Custom Scripted Lookup 
# # TODO 
# 
####

echo "IP Lists" 
################# IPs (IPv4) #################

# Source - Parthdmaniar - Github 
curl https://raw.githubusercontent.com/parthdmaniar/coronavirus-covid-19-SARS-CoV-2-IoCs/master/IPs > IP_Parthdmaniar_github.list.txt
cat IP_Parthdmaniar_github.list.txt | sed -e 's/$/,COVID19_IP_Parthdmaniar_github,isBad/' > LKPTBL_COVID19_IP_Parthdmaniar.csv
# Add Splunk Header for lookups 
sed -i '1i\TIValue,TISource,TILogic' LKPTBL_COVID19_IP_Parthdmaniar.csv
# Splunk - Move to Lookups 
#mv LKPTBL_COVID19_IP_Parthdmaniar.csv 

echo "URL Lists" 
################# URLs #######################

echo " CTC" 
# Source - CTC - URL
# Download
curl https://blacklist.cyberthreatcoalition.org/vetted/url.txt > Cyber_threat_Coalition_url_Blacklist.txt
# Format 
sed -i '1d' Cyber_threat_Coalition_url_Blacklist.txt 
cat Cyber_threat_Coalition_url_Blacklist.txt | sed -e 's/^M/,COVID19_Cyber_Threat_Coalition_VETTED,URL,isBad/' > LKPTBL_CTC_Vetted_URLs.csv
# Add Splunk Header for lookups
sed -i '1i\TIValue,TISource,TILogic' LKPTBL_CTC_Vetted_URLs.csv 
# Splunk - Move to lookups
#mv LKPTBL_CTC_Vetted_URLS.csv

echo " Parthdmanir "
# Source - Parthdmaniar - Github  
curl https://raw.githubusercontent.com/parthdmaniar/coronavirus-covid-19-SARS-CoV-2-IoCs/master/URLs > URL_Parthdmaniar_github_list.txt 
cat URL_Parthdmaniar_github_list.txt | sed -e 's/$/,COVID19_URL_Parthdmaniar_github,isBad/' > LKPTBL_COVID19_URL_Parthdmaniar.csv
# Add Splunk Header for lookups
sed -i '1i\TIValue,TISource,TILogic' LKPTBL_COVID19_URL_Parthdmaniar.csv 
# Splunk - Move to Lookups 
#mv LKPTBL_COVID19_URL_Parthdmaniar.csv 

echo " Phishlabs" 
# PhishLabs - Download required
# STATIC LIST ALREADY LOOKUP 
# FILE ---   LKPTBL_COVID19_URL_PhishLabs.csv
# 
# Manual Steps 
#curl https://www.phishlabs.com/wp-content/uploads/2015/12/COVID-19ThreatIntel042020.zip > URL_PhishLabs_Malicious_Data.zip 
#unzip URL_PhishLabs_Malicious_Data.zip 
#mv COVID-19\ Threat\ Intel/URLs/COVID-19\ Malicious\ URLs.xlsx . 
# Utility - Covert xlsx to csv 
# Pyhon modules required: 
#   rows openpyxl 
# import rows
# data = rows.import_from_xlsx("Phishlabs_Malicious_URLs.xlsx")
# rows.export_to_csv(data, open("Phishlabs_Malicious_URLs.csv", "wb"))
# python Py_Phishlabs_convert_xlsx_to_csv.py
# cat Phishlabs_Malicious_URLs.csv | awk -F"," '{ print $2",COVID19_URL_PhishLabs,isBad" }' > LKPTBL_COVID19_URL_PhishLabs.csv
# Add Splunk Header for lookups
#sed -i '1i\TIValue,TISource,TILogic' LKPTBL_COVID19_URL_PhishLabs.csv 
# Splunk - Move to Lookups 
#mv LKPTBL_COVID19_URL_PhshLabs.csv lookups 


echo "Domain Lists" 
################# Domains ####################

echo " CTC" 
# Source - CTC - Domains
curl https://blacklist.cyberthreatcoalition.org/vetted/domain.txt > Cyber_Threat_Coalition_domain_Blocklist.txt
#Format 
sed -i '1d' Cyber_Threat_Coalition_domain_Blocklist.txt 
cat Cyber_Threat_Coalition_domain_Blocklist.txt | sed -e 's/^M/,COVID19_Cyber_Threat_Coalition_VETTED,Domain,isBad/' > LKPTBL_CTC_Vetted_Domain.csv
# Add Splunk Header for lookups
sed -i '1i\TIValue,TISource,TILogic' LKPTBL_CTC_Vetted_Domain.csv 
# Splunk - Move to lookups
#mv LKPTBL_CTC_Vetted_Domain.csv $SPLUNK_HOME/etc/apps/TA_CyberCovidIOCs/lookups

echo " MerkleID " 
# Source - GitHub - MerkleID
curl https://raw.githubusercontent.com/merkleID/covid-domains/master/full-domains-list.txt > MerkleID_Github_Domain.txt
cat MerkleID_Github_Domain.txt | sed -e 's/^M/,COVID19_MerkleID_Github,Domain,isBad/' > LKPTBL_Domain_MerkleID_Github.csv
# Add Splunk Header for lookups
sed -i '1i\TIValue,TISource,TILogic' LKPTBL_Domain_MerkleID_Github.csv 
# Splunk - Move to lookups
#mv LKPTBL_Domain_MerkleID_Github.csv $SPLUNK_HOME/etc/apps/TA_CyberCovidIOCs/lookups

echo " RiskIQ" 
# Source - RiskIQ
curl https://covid-public-domains.s3-us-west-1.amazonaws.com/list.txt > RiskIQ_Domains.txt 
#Format 
sed -i '1d' RiskIQ_Domains.txt 
cat RiskIQ_Domains.txt | awk -F"," '{ print $3",COVID19_Domain_RiskIQ,isBad" }' > LKPTBL_COVID19_Domain_RiskIQ.csv 
# Add Splunk Header for lookups
sed -i '1i\TIValue,TISource,TILogic' LKPTBL_COVID19_Domain_RiskIQ.csv 
# Splunk - Move to lookups 
#mv LKPTBL_COVID19_Domain_RiskIQ.csv 

echo " 1984_sh " 
# Source -  1984_sh
curl https://1984.sh/covid19-domains-feed.txt > 1984_sh_Domains.txt
# Cut the header out 
sed '1,19d'  1984_sh_Domains.txt > 1984_sh_Domain_list.txt
cat 1984_sh_Domain_list.txt | awk -F"," '{ print $3",COVID19_Domain_1984_sh,isBad" }' > LKPTBL_COVID19_Domain_1984_sh.csv
# Add Splunk Header for lookups
sed -i '1i\TIValue,TISource,TILogic' LKPTBL_COVID19_Domain_1984_sh.csv 
# Splunk - Move to lookups 
#mv LKPTBL_COVID19_Domain_1984_sh.csv 

echo " DomainTools " 
# Source - DomainTools - Download gz CSV
curl https://covid-19-threat-list.domaintools.com/dt-covid-19-threat-list.csv.gz | zcat > DomainTools_Domains.txt 
cat DomainTools_Domains.txt  | awk -F"\t" '{ print $1",COVID19_Domain_DomainTools,isBad" }' > LKPTBL_COVID19_Domain_DomainTools.csv
# Add Splunk Header for lookups
sed -i '1i\TIValue,TISource,TILogic' LKPTBL_COVID19_Domain_DomainTools.csv 
# Splunk - Move to lookups 
#mv LKPTBL_COVID19_Domain_DomainTools.csv 

echo " JAS Global " 
# Source - JAS Global
# Multiple  https://www.jasadvisors.com/covid/
curl https://www.jasadvisors.com/covid/latest.jas.covid.tab > JAS_Global_Domains.txt 
cat JAS_Global_Domains.txt | awk -F"\t" '{ print $1",COVID19_Domain_JAS_Global,isBad" }' > LKPTBL_COVID19_JAS_Global.csv
# Add Splunk Header for lookups
sed -i '1i\TIValue,TISource,TILogic' LKPTBL_COVID19_JAS_Global.csv 
# Splunk - Move to lookups 
#mv LKPTBL_COVID19_JAS_Global.csv 

echo " Malware Patrol " 
# Source - Malware Patrol
# Multiple lists - https://www.malwarepatrol.net/coronavirus-covid-19-online-scams-data/
curl http://malwarepatrolexport-covid-19.s3-website.us-east-2.amazonaws.com/domains/domains.txt > MalwarePatrol_Domains.txt 
cat MalwarePatrol_Domains.txt | awk '{ print $1",COVID19_Domain_MalwarePatrol,isBad" }' > LKPTBL_COVID19_MalwarePatrol.csv
# Add Splunk Header for lookups
sed -i '1i\TIValue,TISource,TILogic' LKPTBL_COVID19_MalwarePatrol.csv 
# Splunk - Move to lookups 
#mv LKPTBL_COVID19_MalwarePatrol.csv 

echo "WHITELIST - Krassi "
# Source - # WHITELIST - Krassi - Github 
curl https://raw.githubusercontent.com/krassi/covid19-related/master/whitelist-domains.txt > WHITELIST_Krassi_github.txt 
cat WHITELIST_Krassi_github.txt | awk '{ print $1",COVID19_WHITELIST_DOMAINS,isGood" }' > LKPTBL_COVID19_WHITELIST_Krassi.csv
# Add Splunk Header for lookups
sed -i '1i\TIValue,TISource,TILogic' LKPTBL_COVID19_WHITELIST_Krassi.csv 
# Splunk - Move to lookups 
#mv LKPTBL_COVID19_WHITELIST_Krassi.csv 


echo 'Hash Lists'
################# Hashes #####################

echo "Parthdmaniar " 
# Source - Parthdmaniar - GitHub (MD5) 
curl https://raw.githubusercontent.com/parthdmaniar/coronavirus-covid-19-SARS-CoV-2-IoCs/master/hashes > HashList_Parthdmaniar.txt 
cat HashList_Parthdmaniar.txt | awk '{ print $1",COVID19_Hash_MD5_Parthdmaniar_Github,isBad" }' > LKPTBL_COVID19_HASH_MD5_Parthdmaniar.csv
# Add Splunk Header for lookups
sed -i '1i\MD5Value,TISource,TILogic' LKPTBL_COVID19_HASH_MD5_Parthdmaniar.csv 
# Splunk - Move to Lookups 
#mv LKPTBL_COVID19_HASH_MD5_Parthdmaniar.csv 

echo "Malware Bazaar" 
# Source - Malware Bazaar Abuse_ch 
curl -d "query=get_taginfo&tag=COVID-19" https://mb-api.abuse.ch/api/v1/ -o HASH_JSON_MalwareBazaar.json
# Because jq is dumb '@csv' no new lines per record 
# python 
# modules json 
##!/bin/python
####
##
## Template pull out fields of interest make CSV
## because jq csv is dumb
##
####
#
#import sys
#import os
#import json
#
## Read in file (STATIC NAME)
#with open('HASH_JSON_MalwareBazaar.json') as json_file:
#        data = json.load(json_file)
#        for p in data['data']:
#                #one line
#                SHA256_Str = str(p['sha256_hash'])
#                SHA1_Str = str(p['sha1_hash'])
#                MD5_Str = str(p['md5_hash'])
#                SignName = str(p['signature'])
#                print SHA256_Str + ',' + SHA1_Str + ',' + MD5_Str + ',' + SignName + ',COVID19_Hash_Multiple_MalwareBzaar,isBad'
python Py_HASHJSON.py > LKPTBL_COVID19_HASH_Malware_Bazaar.csv 
# Add Splunk Header for lookups
sed -i '1i\SHA256Value,SHA1Value,MD5Value,SignName,TISource,TILogic' LKPTBL_COVID19_HASH_Malware_Bazaar.csv  
# Splunk - Move to lookups 
#mv LKPTBL_COVID19_HASH_Malware_Bazaar.csv 

################# SOURCES LIST #################
####### CTI League
############ Same as our CTC 
############     https://github.com/COVID-19-CTI-LEAGUE/PUBLIC_RELEASE
##
####### Github - Parthdmaniar - has all IOCs and CVEs 
############     https://github.com/parthdmaniar/coronavirus-covid-19-SARS-CoV-2-IoCs
##
############ Additional Sources
##
####### Sources Full List
###########      https://github.com/MishcondeReya/Covid-19-CTI

echo "Cleanup Tasks " 

# Cleanup - Move files to lookups 
#Manual 
mv *.csv ../lookups 
mv *.json ../lookups 
#Splunk 
#mv *.csv $SPLUNK_HOME/etc/apps/TA_CyberCOVID19/lookups/
#mv *.json $SPLUNK_HOME/etc/apps/TA_CyberCOVID19/lookups/ 

# Cleanup - Remove download files (.txt)
rm  *.txt 


