#!/bin/python 

import sys 
import os 
import requests 

REQ_DNS_File_Name = "covid_DNS_ALL.csv" 

# Source - Malware Patrol
# NOTE Malware Patrol has several lists available using the DNS/Domain one
DNS_Source_11 = "http://malwarepatrolexport-covid-19.s3-website.us-east-2.amazonaws.com/domains/domains.txt"
REQ_DNS_Source_11 = requests.get(DNS_Source_11)
#DEBUG
print "DNS Source 11 Status is: " + str(REQ_DNS_Source_11.status_code)
if (REQ_DNS_Source_11.status_code == 200):
	# URL is good to download
	content_bytes11 = REQ_DNS_Source_11.headers.get("Content-Length")
	print "DNS Malware Patrol - Size " + str(content_bytes11)
	DNS_File = open(REQ_DNS_File_Name, "a+")
	Source11_counter = 0
	# write out line by line
	for line in REQ_DNS_Source_11.iter_lines():
		if line:
			DNS_line = line + ",COVID21_Domain_MalwarePatrol,isBad" + "\n"
			DNS_File.write(DNS_line)
			Source11_counter += 1
	DNS_File.close()
	print "Wrote " + str(Source11_counter) + " lines "
else:
	print "ERROR: Source 11 - Malware Patrol DNS Failed"
