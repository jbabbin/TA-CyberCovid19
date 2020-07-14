#!/bin/python 
### 
# 
# Template pull out fields of interest make CSV 
# because jq csv is dumb 
#
###

import sys
import os 
import json 

# Read in file (STATIC NAME) 
with open('HASH_JSON_MalwareBazaar.json') as json_file: 
	data = json.load(json_file)
	for p in data['data']:
		#one line 
		SHA256_Str = str(p['sha256_hash']) 
		SHA1_Str = str(p['sha1_hash'])
		MD5_Str = str(p['md5_hash'])
		SignName = str(p['signature']) 
		print SHA256_Str + ',' + SHA1_Str + ',' + MD5_Str + ',' + SignName + ',COVID19_Hash_Multiple_MalwareBzaar,isBad'
