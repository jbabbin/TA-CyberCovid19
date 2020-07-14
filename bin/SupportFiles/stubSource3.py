import sys 
import os 
import requests
import re 
import subprocess 

#Common header - 3 column TIValue, TISource, TILogic
# first row create header as string write to file
headerStr = "TIValue, TISource, TILogic" + "\n"

REQ_URL_File_Name = "CyberCOVID_URL.csv"
# Create header
URL_File = open(REQ_URL_File_Name, "w+")
URL_File.write(headerStr)
URL_File.close()

# 3 Source - CTC Vetted
URL_Source_3 = "https://blacklist.cyberthreatcoalition.org/vetted/url.txt"
REQ_URL_Source_3 = requests.get(URL_Source_3)
#Debug
print "URL Source 3 Status is: " + str(REQ_URL_Source_3.status_code)
if (REQ_URL_Source_3.status_code == 200):
        # URL is good download
        content_bytes3 = REQ_URL_Source_3.headers.get("Content-Length")
	REQ_Headers = REQ_URL_Source_3.headers
	print "Headers [" 
	print REQ_Headers 
	print  "]" 
        print "URL CTC Vetted - Size " + str(content_bytes3)
        #URL_File = open("covid_URL_CTC.csv", "w+")
        URL_File = open(REQ_URL_File_Name, "a+")
        #URL_File.write(headerStr)
        # write out line by line
        # Skip header line Only 1 line
        #with open('yourfile.txt') as f:
        #    lines_after_17 = f.readlines()[17:]
	counter = 0 
        for line in REQ_URL_Source_3.iter_lines():
                if line:
                        URL_line = line + ",COVID19_Cyber_Threat_Coalition_VETTED,URL,isBad" +  "\n"
                        URL_File.write(URL_line)
			counter += 1
        URL_File.close()
	print "Wrote " + str(counter) + " lines" 
        # Cleanup Remove header line(s)
       # Cleanup Remove header line(s)
        # Use system command 'sed' for efficency
        # sed -i -e "1d" $FILE
	Sed_Str = "sed -i -e '2d' CyberCOVID_URL.csv" 
        subprocess.call(Sed_Str, shell=True)

else:
        print "ERROR: Source 3 - CTC URL Failed "

print "Temp Stop - source 3 "
sys.exit()


