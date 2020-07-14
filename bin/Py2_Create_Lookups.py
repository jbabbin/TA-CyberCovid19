#!/bin/python 

################################################################
#
# Title: CyberCOVID Splunk Lookup Collection  
# Author: CTC - Jake Babbin Copper River 
# Date: 13 July 2020  
#
# REQUIREMENTS: 
#   Python Libraries: 
#	simplejson (or json) 
#	requests
#
# USAGE:
#  prompt> python Py2_Create_Lookups.py 
#
# TODO: 
#
# BUGS: 
#
# VERSION:
#
################################################################

import sys 
import os 
import re 
import requests 
import subprocess 
import zlib 
import json

###### Download all lists by type of data 
# IP, URLs, Domains, hash values, etc 

# Create single file by Type of IOC 
# IP - CyberCOVID_IP.csv 
# URL - CyberCOVID_URL.csv 
# Domain - CyberCOVID_DNS.csv 
# Hash - CyberCOVID_Hash.csv 

################################### GLOBAL VARIABLES ################################################

# Files for the CSV 
REQ_IP_File_Name = "CyberCOVID_IP.csv" 
REQ_URL_File_Name = "CyberCOVID_URL.csv" 
REQ_DNS_File_Name = "CyberCOVID_DNS.csv"
REQ_HASH_File_Name = "CyberCOVID_HASH.csv"


#Common header - 3 column TIValue, TISource, TILogic 
# first row create header as string write to file 
headerStr = "TIValue, TISource, TILogic" + "\n" 

################################### BEGIN COLLECTION OF SOURCES #####################################

print "Begining CyberCOVID Source Collection "

########### IP (IPv4)##############

print "\n##################### IP ####################\n"

# 1 Source - Parthdmaniar - Github 
IP_Source_1 = "https://raw.githubusercontent.com/parthdmaniar/coronavirus-covid-19-SARS-CoV-2-IoCs/master/IPs" 
REQ_IP_Source_1 = requests.get(IP_Source_1) 
#Debug  
print "\tIP Source 1 Status is: " + str(REQ_IP_Source_1.status_code)
if (REQ_IP_Source_1.status_code == 200): 
	# URL is good download 
	# Check for file Size of 0 bytes
	content_bytes2 = REQ_IP_Source_1.headers.get("Content-Length")
	print "\tIP Parthdmaniar - Size " + content_bytes2         
	IP_file = open(REQ_IP_File_Name, "w+") 
	IP_file.write(headerStr) 
	Source1_counter = 0 
	# write out line by line 
	for line in REQ_IP_Source_1.iter_lines():
		if line: 
			IP_line = line + ",COVID19_IP_Parthdmaniar_github,isBad" + "\n" 
			IP_file.write(IP_line)
			Source1_counter += 1 
			#DEBUG - make sure printing out lines 
			#print IP_line 
	IP_file.close()  
	print "\tWrote " + str(Source1_counter) + " lines" 
else: 
	print "\t\tERROR: Failed - IP - Parthdmaniar Failed" 

print "\tdownload completes - Next Source" 

# 2 Source - CTC vetted (Coming Soon)

print "\tPLACEHOLDER - CTC IP LIST"
print "\n############################################\nIP sources complete Stopping" 


########### URLs ##################

print "\n###################### URLs #################\n"

# Create header 
URL_File = open(REQ_URL_File_Name, "w+")
URL_File.write(headerStr)
URL_File.close() 

# 3 Source - CTC Vetted 
URL_Source_3 = "https://blacklist.cyberthreatcoalition.org/vetted/url.txt"
REQ_URL_Source_3 = requests.get(URL_Source_3) 
#Debug  
print "\tURL Source 3 Status is: " + str(REQ_URL_Source_3.status_code)
if (REQ_URL_Source_3.status_code == 200):
	# URL is good download 
	# Check file size of 0 bytes 
	content_bytes3 = REQ_URL_Source_3.headers.get("Content-Length")
	print "\tURL CTC Vetted - Size " + str(content_bytes3) 
	# NOTE 
	# Sometimes for Cloudflare sites this header is either missing or reads as '0' 
	# the counter helps to show data is still there 
	URL_File = open(REQ_URL_File_Name, "a+")
	Source3_counter = 0
	for line in REQ_URL_Source_3.iter_lines():
        	if line:
                	URL_line = line + ",COVID19_Cyber_Threat_Coalition_VETTED,URL,isBad" +  "\n"
                	URL_File.write(URL_line)
			Source3_counter += 1 
	URL_File.close()
	print "\tWrote " + str(Source3_counter) + " lines "

	# Cleanup Remove header line(s) 
	# Use system command 'sed' for efficency 
	# Only one line to remove line 2 as line 1 is now the header 
	Sed_Str = "sed -i -e '2d' CyberCOVID_URL.csv"
	subprocess.call(Sed_Str, shell=True)
else: 
	print "\t\tERROR: Source 3 - CTC URL Failed " 

print "\tdownload complete - Next Source" 

# 4 Source - Parthdmaniar  
URL_Source_4 = "https://raw.githubusercontent.com/parthdmaniar/coronavirus-covid-19-SARS-CoV-2-IoCs/master/URLs" 
REQ_URL_Source_4 = requests.get(URL_Source_4) 
#Debug  
print "\tURL Source 4 Status is: " + str(REQ_URL_Source_4.status_code) 
if (REQ_URL_Source_4.status_code == 200):
	#URL is good download 
	# Check file size of 0 bytes 
	content_bytes4 = REQ_URL_Source_4.headers.get("Content-Length") 
	print "\tURL Parthdmaniar - Size " + content_bytes4 
	URL_File = open(REQ_URL_File_Name, "a+")
	Source4_counter = 0 
	for line in REQ_URL_Source_4.iter_lines():
		if line: 
			URL_line = line + ",COVID19_URL_Parthdmaniar_github,isBad" + "\n" 
			URL_File.write(URL_line) 
			Source4_counter += 1 
	URL_File.close() 
	print "\twrote " + str(Source4_counter) + " lines" 
	# No headers to cleanup 
else: 
	print "\t\tERROR: Source 4 - Parthdmaniar URL Failed " 
	
print "\tdownload complete - Next Source" 

# 5 Source - PhishLabs 
# Removed - requires a subscription and an email 
#

print "\n############################################\nURL sources complete Stopping"

########### Domain/DNS ############

print "\n###################### Domainss #################\n"

# Create header
DNS_File = open(REQ_DNS_File_Name, "w+")
DNS_File.write(headerStr)
DNS_File.close()


# 5 Source - Domain - CTC 
DNS_Source_5 = "https://blacklist.cyberthreatcoalition.org/vetted/domain.txt" 
REQ_DNS_Source_5 = requests.get(DNS_Source_5)
#Debug 
print "\tDNS Source 5 Status is: " + str(REQ_DNS_Source_5.status_code) 
if (REQ_DNS_Source_5.status_code == 200): 
	# URL is good download 
	# Check file size of 0 bytes 
	content_bytes5 = REQ_DNS_Source_5.headers.get("Content-Length")
	print "\tDNS CTC - Size " + str(content_bytes5) 
	DNS_File = open(REQ_DNS_File_Name, "a+") 
	# Write out line by line 
	Source5_counter = 0 
	for line in REQ_DNS_Source_5.iter_lines():
		if line: 
			DNS_line = line  + ",COVID19_Cyber_Threat_Coalition_VETTED,Domain,isBad" + "\n"  
			DNS_File.write(DNS_line) 
			Source5_counter += 1
	DNS_File.close() 
	print "\twrote " + str(Source5_counter) + " lines" 
	# Cleanup Header - removal 
        # Use system command 'sed' for efficency
        # Only one line to remove line 2 as line 1 is now the header
        Sed_Str = "sed -i -e '2d' CyberCOVID_DNS.csv"
        subprocess.call(Sed_Str, shell=True)

else: 
	print "\t\tERROR: Source 5 - CTC DNS Failed " 

# 6 - Source - MerkleID  
DNS_Source_6 = "https://raw.githubusercontent.com/merkleID/covid-domains/master/full-domains-list.txt" 
REQ_DNS_Source_6 = requests.get(DNS_Source_6) 
#Debug 
print "\tDNS Source 6 Status is: " + str(REQ_DNS_Source_6.status_code) 
if (REQ_DNS_Source_6.status_code == 200): 
	#URL is good download 
	content_bytes6 = REQ_DNS_Source_6.headers.get("Content-Length")
	print "\tDNS MerkleID - Size " + str(content_bytes6) 
	DNS_File = open(REQ_DNS_File_Name, "a+")
	# Write out line by line 
	Source6_counter = 0 
	for line in REQ_DNS_Source_6.iter_lines():
		if line: 
			DNS_line = line + ",COVID19_MerkleID_Github,Domain,isBad" + "\n" 
			DNS_File.write(DNS_line)
			Source6_counter += 1 
	DNS_File.close() 
	print "\twrote " + str(Source6_counter) + " lines" 
	# Cleanup 
	# sed '/^#/d' - removes all lines with # in the start 
	Sed_Str = "sed -i '/^#/d' CyberCOVID_DNS.csv" 
	subprocess.call(Sed_Str, shell=True)
else: 
	print "\t\tERROR: Source 6 - MerkleID Failed " 

# 7 - Source - RiskIQ 
DNS_Source_7 = "https://covid-public-domains.s3-us-west-1.amazonaws.com/list.txt"
REQ_DNS_Source_7 = requests.get(DNS_Source_7) 
#Debug 
print "\tDNS Source 7 Status is: " + str(REQ_DNS_Source_7.status_code) 
if (REQ_DNS_Source_7.status_code == 200): 	
	# URL is good download 
	content_bytes7 = REQ_DNS_Source_7.headers.get("Content-Length")
	print "\tDNS RiskIQ - Size " + str(content_bytes7) 
	DNS_File = open(REQ_DNS_File_Name, "a+")
	#write out line by line 
	Source7_counter = 0 
	for line in REQ_DNS_Source_7.iter_lines():
		if line:
			# Formatting - only grab the 3rd column 
			line_arr = line.split(',') 
			line = line_arr[2]
			DNS_line = line + ",COVID19_Domain_RiskIQ,isBad" + "\n" 
			DNS_File.write(DNS_line)
			Source7_counter += 1 
	DNS_File.close() 
	print "\twrote " + str(Source7_counter) + " lines" 
	#Cleanup 
	Sed_Str = "sed -i '/^#/d' CyberCOVID_DNS.csv" 
	subprocess.call(Sed_Str, shell=True) 
else: 
	print "\t\tERROR: Source 7 - RiskIQ DNS Failed" 

# 8 - Source - 1984.sh 
DNS_Source_8 = "https://1984.sh/covid19-domains-feed.txt"
REQ_DNS_Source_8 = requests.get(DNS_Source_8)
#DEBUG 
print "\tDNS Source 8 Status is:" + str(REQ_DNS_Source_8.status_code)
if (REQ_DNS_Source_8.status_code == 200):
	# URL is good to download 
	content_bytes8 = REQ_DNS_Source_8.headers.get("Content-Length")
	print "\tDNS 1984 - Size " + str(content_bytes8) 
	DNS_File = open(REQ_DNS_File_Name, "a+")
	#write out line by line
	Source8_counter = 0 
	for line in REQ_DNS_Source_8.iter_lines():
		# Skip the first few lines that don't start with a date
		if line.startswith('2020'):
			# Formatting - only grab the 3rd column 
			line_arr = line.split(',')
			line = line_arr[2] 
			DNS_line = line + ",COVID19_Domain_1984_sh,isBad" + "\n"
			DNS_File.write(DNS_line)
			Source8_counter += 1 
	DNS_File.close()
	print "\twrote " + str(Source8_counter) + " lines" 
	#Cleanup - done in formatting 
else:
	print "\t\tERROR: Source 8 - 1984_sh DNS Failed" 

# 9 - Source - DomainTools 
DNS_Source_9 = "https://covid-19-threat-list.domaintools.com/dt-covid-19-threat-list.csv.gz"
REQ_DNS_Source_9 = requests.get(DNS_Source_9)
#DEBUG 
print "\tDNS Source 9 Status is: " + str(REQ_DNS_Source_9.status_code)
if (REQ_DNS_Source_9.status_code == 200):
	# URL is good to download 
	content_bytes9 = REQ_DNS_Source_9.headers.get("Content-Length")
	print "\tDNS DomainTools - Size " + str(content_bytes9) 
	DNS_File = open(REQ_DNS_File_Name, "a+")
	ContentGzip = REQ_DNS_Source_9 
	UncompressedData = zlib.decompress(ContentGzip.content, zlib.MAX_WBITS|32)
	Source9_counter = 0 
	#write out line by line 
	for line in UncompressedData.splitlines():
		#DEBUG 
		#print "Raw Line [" + line + "]" 
		line_arr = line.split(None,1)
		line = line_arr[0]
		DNS_line = line + ",COVID19_Domain_DomainTools,isBad" + "\n" 
		DNS_File.write(DNS_line)
		Source9_counter += 1 
	DNS_File.close()
	print "\twrote " + str(Source9_counter) + " lines"
	# Cleanup - none 
else: 
	print "\t\tERROR: Source 9 - DomainTools DNS Failed" 

# 10 - Source - JAS Global 
DNS_Source_10 = "https://www.jasadvisors.com/covid/latest.jas.covid.tab"
REQ_DNS_Source_10 = requests.get(DNS_Source_10)
#DEBUG 
print "\tDNS Source 10 Status is: " + str(REQ_DNS_Source_10.status_code)
if (REQ_DNS_Source_10.status_code == 200):
	#URL is good to download 
	content_bytes10 = REQ_DNS_Source_10.headers.get("Content-Length")
	print "\tDNS JAS_Global - Size " + str(content_bytes10)
	DNS_File = open(REQ_DNS_File_Name, "a+")
	Source10_counter = 0 
	# write out line by line 
	for line in REQ_DNS_Source_10.iter_lines():
		if not line.startswith('domain'):
			line_arr = line.split('\t')
			line = line_arr[0]
			DNS_line = line + ",COVID19_Domain_JASGlobal,isBad" + "\n" 
			DNS_File.write(DNS_line) 
			Source10_counter += 1 
	DNS_File.close()
	print "\twrote " + str(Source10_counter) + " lines" 
	# Cleanup - None 
else: 
	print "\t\t\ERROR: Source 10 - JAS Global DNS Failed" 
		
# 11 - Source - Malware Patrol 
# NOTE Malware Patrol has several lists available using the DNS/Domain one 
DNS_Source_11 = "http://malwarepatrolexport-covid-19.s3-website.us-east-2.amazonaws.com/domains/domains.txt" 
REQ_DNS_Source_11 = requests.get(DNS_Source_11)
#DEBUG 
print "\tDNS Source 11 Status is: " + str(REQ_DNS_Source_11.status_code)
if (REQ_DNS_Source_11.status_code == 200):
	# URL is good to download 
	content_bytes11 = REQ_DNS_Source_11.headers.get("Content-Length")
	print "\tDNS Malware Patrol - Size " + str(content_bytes11)
	DNS_File = open(REQ_DNS_File_Name, "a+")
	Source11_counter = 0 
	# write out line by line 
	for line in REQ_DNS_Source_11.iter_lines():
		if line: 
			DNS_line = line + ",COVID19_Domain_MalwarePatrol,isBad" + "\n" 
			DNS_File.write(DNS_line)
			Source11_counter += 1 
	DNS_File.close() 
	print "\tWrote " + str(Source11_counter) + " lines " 
else: 
	print "\t\tERROR: Source 11 - Malware Patrol DNS Failed" 


# 12 - Source - Whitelist Krassi Github 
DNS_Source_12 = "https://raw.githubusercontent.com/krassi/covid19-related/master/whitelist-domains.txt"
REQ_DNS_Source_12 = requests.get(DNS_Source_12)
#DEBUG
print "\tDNS Source 12 Status is: " + str(REQ_DNS_Source_12.status_code)
if (REQ_DNS_Source_12.status_code == 200):
        #URL is good to download
        content_bytes12 = REQ_DNS_Source_12.headers.get("Content-Length")
        print "\tDNS WHITELIST Krassi - Size " + str(content_bytes12)
        DNS_File = open(REQ_DNS_File_Name, "a+")
        Source12_counter = 0
        # write out line by line
        for line in REQ_DNS_Source_12.iter_lines():
		if line: 
			DNS_line = line + ",COVID19_Domain_KrassiGithub,isGood" + "\n"	
                        DNS_File.write(DNS_line)
                        Source12_counter += 1
        DNS_File.close()
        print "\twrote " + str(Source12_counter) + " lines"
        # Cleanup - None
else:
        print "\t\tERROR: Source 12 - WHITELIST krassi  DNS Failed"

print "\n############################################\nDomain sources complete Stopping"
	
########### Hash (mutiple types) ##

print "\n###################### HASH #################\n"

# Create header
HASH_File = open(REQ_HASH_File_Name, "w+")
HASH_File.write(headerStr)
HASH_File.close()

# 13 - Source - HASH - Parthdmaniar - Github
HASH_Source_13 = "https://raw.githubusercontent.com/parthdmaniar/coronavirus-covid-19-SARS-CoV-2-IoCs/master/hashes"
REQ_HASH_Source_13 = requests.get(HASH_Source_13)
#DEBUG
print "\tHASH Source 13 Status is: " + str(REQ_HASH_Source_13.status_code)
if (REQ_HASH_Source_13.status_code == 200):
        #URL is good to download
        content_bytes13 = REQ_HASH_Source_13.headers.get("Content-Length")
        print "\tHASH parthdmaniar - Size " + str(content_bytes13)
        HASH_File = open(REQ_HASH_File_Name, "a+")
        Source13_counter = 0
        # write out line by line
        for line in REQ_HASH_Source_13.iter_lines():
		if line: 
			HASH_line = line + ",COVID19_HASH_MD5_parthdmaniar,isBad" + "\n"	
                        HASH_File.write(HASH_line)
                        Source13_counter += 1
        HASH_File.close()
        print "\twrote " + str(Source13_counter) + " lines"
        # Cleanup - None
else:
        print "\t\tERROR: Source 13 - HASH MD5 Parthdmaniar Failed"

# 14 - Source HASH Malware Bazaar 
Payload14 = {'query': 'get_taginfo', 'tag': 'COVID-19'}
HASH_Source_14 = "https://mb-api.abuse.ch/api/v1/" 
REQ_HASH_Source_14 = requests.post(HASH_Source_14, data=Payload14)

print "\tHASH Source 14 Status is: " + str(REQ_HASH_Source_14.status_code) 
if (REQ_HASH_Source_14.status_code == 200):
	# URL is good to download 
	content_bytes14 = REQ_HASH_Source_14.headers.get("Content-Length")
	print "\tHASH Malware Bazaar - Size " + str(content_bytes14) 
	HASH_File = open(REQ_HASH_File_Name, "a+")
	Source14_counter = 0 
	#print "Raw " 
#	print(REQ_HASH_Source_14.text)
	Source14_JSON = json.loads(REQ_HASH_Source_14.text)
	for p in Source14_JSON['data']:
                #one line
                SHA256_Str = str(p['sha256_hash'])
                SHA1_Str = str(p['sha1_hash'])
                MD5_Str = str(p['md5_hash'])
                SignName = str(p['signature'])
                # MD5, SHA1, and SHA256 available 
		#print SHA256_Str + ',' + SHA1_Str + ',' + MD5_Str + ',' + SignName + ',COVID19_Hash_Multiple_MalwareBzaar,isBad'
		# MD5 only for Lookups 
		#DEBUG 
		#print MD5_Str + ',_' + SignName + '_COVID19_Hash_MD5_MalwareBazaar,isBad' 
		HASH_line = MD5_Str + ',_' + SignName + "_COVID19_Hash_MD5_MalwareBazaar,isBad" + "\n"
		HASH_File.write(HASH_line)
		Source14_counter += 1
	HASH_File.close()
	print "\twrote " + str(Source14_counter) + " lines" 
else: 
	print "\t\tERROR: Source 14 - HASH MalwareBazaar - Failed"

print "\n############################################\nHASH sources complete Stopping"

########################## Move CSV files to Lookups path 

print "Cleanup Tasks" 

# Cleanup - Move files to lookups
#Manual
MoveCSV_str = "mv *.csv ../lookups"
subprocess.call(MoveCSV_str, shell=True)


#mv *.json ../lookups
#Splunk
#mv *.csv $SPLUNK_HOME/etc/apps/TA_CyberCOVID19/lookups/
#mv *.json $SPLUNK_HOME/etc/apps/TA_CyberCOVID19/lookups/

