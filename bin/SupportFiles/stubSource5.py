# 5 Source - PhishLabs
# Example URL
# https://www.phishlabs.com/wp-content/uploads/2015/12/COVID-19ThreatIntel042020.zip
# Steps
# Get previous data for the zip file name
# Download the zip leaving the xslx file
# covert the xlsx to csv then grab content for lookup

import os 
import sys 
import subprocess 

from datetime import datetime, timedelta
PrevDay = datetime.strftime(datetime.now() - timedelta(1), '%m%d%Y')
Phish_URL_Str = "wget " + "https://www.phishlabs.com/wp-content/uploads/2015/12/COVID-19ThreatIntel" + PrevDay + ".zip"
print "Source 5 - File name " + Phish_URL_Str
subprocess.call(Phish_URL_Str, shell=True)
print "Source 5 - PhishLabs - Download of Zip Complete"

import rows
data = rows.import_from_xlsx("Phishlabs_Malicious_URLs.xlsx")
rows.export_to_csv(data, open("Phishlabs_Malicious_URLs.csv", "wb"))


print " URL Sources complete - Stopping "

