#!/bin/python 

import sys 
import os 
import requests 

REQ_DNS_File_Name = "covid_DNS_ALL.csv"

# 12 - Source - WHITELIST - krassi Github 
DNS_Source_12 = "https://raw.githubusercontent.com/krassi/covid19-related/master/whitelist-domains.txt"
REQ_DNS_Source_12 = requests.get(DNS_Source_12)
#DEBUG
print "DNS Source 12 Status is: " + str(REQ_DNS_Source_12.status_code)
if (REQ_DNS_Source_12.status_code == 200):
        #URL is good to download
        content_bytes12 = REQ_DNS_Source_12.headers.get("Content-Length")
        print "DNS WHITELIST Krassi - Size " + str(content_bytes12)
        DNS_File = open(REQ_DNS_File_Name, "a+")
        Source12_counter = 0
        # write out line by line
        for line in REQ_DNS_Source_12.iter_lines():
		if line: 
			DNS_line = line + ",COVID19_Domain_KrassiGithub,isGood" + "\n"	
                        DNS_File.write(DNS_line)
                        Source12_counter += 1
        DNS_File.close()
        print "wrote " + str(Source12_counter) + " lines"
        # Cleanup - None
else:
        print "ERROR: Source 12 - WHITELIST krassi  DNS Failed"
