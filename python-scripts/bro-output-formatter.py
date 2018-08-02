import urllib.request
import re


intel_type = {'IP' : '::ADDR' , 'DOMAINS' : '::DOMAIN' , 'URLS' : 'URL' , 'SHA-1' : '::CERT_HASH'}


raw_intel = open('formatted-intel.txt', 'r')
#total_intel = raw_intel.read().splitlines()


output = open('bro-intel.txt','w')

for intel in raw_intel:
    #print(intel)
    #print(source)
    details = intel.split()
    #print(details)
    meta_src = details[0]

##        raw_data = urllib.request.urlopen(url)
##
##        data = list ( set ( raw_data.read().decode('utf-8').splitlines() ) )

    #meta_desc= desc(data[0])
    meta_desc=details[4]
    field = details[3]
    meta_url=details[1]
    indicator = intel_type[details[2].upper()]
    line = [field, indicator, meta_src, meta_desc, meta_url]
    #   print(line)

##        for intel in data:
##            line=[]
##            line.append(intel)
##            
##            if re.search('[a-zA-Z]', intel):
##                line.append("Intel::DOMAIN")
##            else:
##                line.append("Intel::ADDR")
##            line.append(src)
##            line.append(meta_desc)
##            line.append(url)
        
    output.write("  ".join(line)+'\n')
        


output.close()






