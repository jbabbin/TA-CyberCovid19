


## Splunk TA-CyberCOVID19

This Splunk app was created to provide all (finding more of course!) of current sources to those who are fighting the Cyber attacks related to COVID.

<b> New Python re-write - Changed the Lookup table names to simplify by IoC type </b>

There are other projects that provide similar efforts:

Splunk Team - https://github.com/splunk/ta-covidiocs

CTC group - https://github.com/secdevopsteam/splunk-covid-hunt


<h2> Splunk instructions</h2>

1. download/clone this repo
2. install to '$SPLUNK_HOME/etc/apps' like any other TA
3. Use Searches

<mark>Edit the inputs.conf to apply the Python re-write </mark>

<h3>Splunk Examples</h3>

    SPL> mysearch_web_logs | lookup  CyberCOVID_DNS

<h3>pre-load the lookup</h3>

    SPL> mysearch_web_logs | [ | inputlookup CyberCOVID_DNS | fields value, TIsource, logic ]

<h4> Splunk Lookup table names </h4> 

    covid_DNS_List
    covid_IP_List
    covid_URL_List
    covid_HASH_List

##############################

Author: CTC Member - Jake Babbin

Version: 2.0

<h2>SOURCES for the Lookup files </h2>

 - Malware Bazaar - Tag COVID-19
 https://bazaar.abuse.ch/browse/tag/COVID-19/
 API Key (needed)
		
- GitHub - MerkleID
https://github.com/merkleID/covid-domains

- CTI League
Though their sources are ours in the CTC ...
https://github.com/COVID-19-CTI-LEAGUE/PUBLIC_RELEASE

- CTC
blacklist.cyberthreatcoalition.org/vetted/domain.txt
blacklist.cyberthreatcoalition.org/vetted/url.txt

- Github - Parthdmaniar
https://github.com/parthdmaniar/coronavirus-covid-19-SARS-CoV-2-IoCs

- RiskIQ
https://covid-public-domains.s3-us-west-1.amazonaws.com/list.txt

- 1984_sh
https://1984.sh/covid19-domains-feed.txt

- DomainTools - Download gz CSV
https://covid-19-threat-list.domaintools.com/dt-covid-19-threat-list.csv.gz

- JAS Global
Multiple Lists and types  
https://www.jasadvisors.com/covid/
https://www.jasadvisors.com/covid/latest.jas.covid.tab

- PhishLabs - Download required
https://www.phishlabs.com/wp-content/uploads/2015/12/COVID-19ThreatIntel042020.zip?submissionGuid=833922d7-6a7f-4766-a550-373874977526

- Malware Patrol
Multiple lists - https://www.malwarepatrol.net/coronavirus-covid-19-online-scams-data/
http://malwarepatrolexport-covid-19.s3-website.us-east-2.amazonaws.com/domains/domains.txt

- GitHub - Krassi
<B> Only WhiteList at the moment 
https://github.com/krassi/covid19-related

## Additional Sources (if you want to add more lookups)
Sources Full List
 https://github.com/MishcondeReya/Covid-19-CTI



