#!/bin/python 

import sys 
import os 
import requests 

REQ_HASH_File_Name = "covid_HASH_ALL.csv"

# 13 - Source - HASH - Parthdmaniar - Github
HASH_Source_13 = "https://raw.githubusercontent.com/parthdmaniar/coronavirus-covid-19-SARS-CoV-2-IoCs/master/hashes"
REQ_HASH_Source_13 = requests.get(HASH_Source_13)
#DEBUG
print "HASH Source 13 Status is: " + str(REQ_HASH_Source_13.status_code)
if (REQ_HASH_Source_13.status_code == 200):
        #URL is good to download
        content_bytes13 = REQ_HASH_Source_13.headers.get("Content-Length")
        print "HASH parthdmaniar - Size " + str(content_bytes13)
        HASH_File = open(REQ_HASH_File_Name, "a+")
        Source13_counter = 0
        # write out line by line
        for line in REQ_HASH_Source_13.iter_lines():
		if line: 
			HASH_line = line + ",COVID19_HASH_MD5_parthdmaniar,isBad" + "\n"	
                        HASH_File.write(HASH_line)
                        Source13_counter += 1
        HASH_File.close()
        print "wrote " + str(Source13_counter) + " lines"
        # Cleanup - None
else:
        print "ERROR: Source 13 - HASH MD5 Parthdmaniar Failed"
