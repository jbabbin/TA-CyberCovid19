#!/bin/python 

import sys 
import os 
import requests 

REQ_DNS_File_Name = "covid_DNS_ALL.csv"

# 10 - Source - JAS Global
DNS_Source_10 = "https://www.jasadvisors.com/covid/latest.jas.covid.tab"
REQ_DNS_Source_10 = requests.get(DNS_Source_10)
#DEBUG
print "DNS Source 10 Status is: " + str(REQ_DNS_Source_10.status_code)
if (REQ_DNS_Source_10.status_code == 200):
        #URL is good to download
        content_bytes10 = REQ_DNS_Source_10.headers.get("Content-Length")
        print "DNS JAS_Global - Size " + str(content_bytes10)
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
        print "wrote " + str(Source10_counter) + " lines"
        # Cleanup - None
else:
        print "ERROR: Source 10 - JAS Global DNS Failed"
