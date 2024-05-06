import tempfile
import sys
import base64
import requests
sys.stdout.reconfigure(encoding='utf-8')
from tld import get_fld
import tldextract  # need to pip install from terminal before importing


first = str(sys.argv[1]) # path to HAR file
second = str(sys.argv[2]) # API Key

unextracted = []
extracted = []
extracted1 = []
extracted2 = []
extracted3 = []
extracted4 = []



with open(first, encoding="utf-8") as f:


    for count, line in enumerate(f):
        if '"url":' in line:
            unextracted.append(line)

    char1 = '"url":'
    char2 = ','
    char3 = '"'
    char4 = ' '

    extracted1 = [i.replace(char1, '') for i in unextracted]
    extracted2 = [i.replace(char2, '') for i in extracted1]
    extracted3 = [i.replace(char3, '') for i in extracted2]
    extracted4 = [i.replace(char4, '') for i in extracted3]




unique_list = list(set(extracted4)) 
  

vurl = "https://www.virustotal.com/api/v3/urls/"


headers = {
    "accept": "application/json",
    "x-apikey": second,
}  
 


uniquee = []
for item2 in unique_list:       
    ext2 = tldextract.extract(item2)
    unique_listy = ext2.registered_domain
    if ext2.registered_domain not in uniquee:
        uniquee.append(ext2.registered_domain)


for i in uniquee:    
    resID = base64.urlsafe_b64encode(i.encode()).decode().strip("=")
    resfinal = vurl + resID
    print(resfinal + '<--------->' + i)
    response = requests.get(resfinal, headers=headers)
    print(response.text + '***************************************************************************************************')
        
     




   






           
            
