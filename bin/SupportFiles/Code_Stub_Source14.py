#!/bin/python 

import sys 
import os 
import requests 

import json

REQ_HASH_File_Name = "covid_HASH_all.csv" 


# 14 - Source HASH Malware Bazaar 
Payload14 = {'query': 'get_taginfo', 'tag': 'COVID-19'}
HASH_Source_14 = "https://mb-api.abuse.ch/api/v1/" 
REQ_HASH_Source_14 = requests.post(HASH_Source_14, data=Payload14)

print "HASH Source 14 Status is: " + str(REQ_HASH_Source_14.status_code) 
if (REQ_HASH_Source_14.status_code == 200):
	# URL is good to download 
	content_bytes14 = REQ_HASH_Source_14.headers.get("Content-Length")
	print "HASH Malware Bazaar - Size " + str(content_bytes14) 
	HASH_File = open(REQ_HASH_File_Name, "a+")
	Source14_counter = 0 
	print "Raw " 
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
	print "wrote " + str(Source14_counter) + " lines" 
else: 
	print "ERROR: Source 14 - HASH MalwareBazaar - Failed"
