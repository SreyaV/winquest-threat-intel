import urllib.request
import re

sources = open('sources.txt', 'r')
info = sources.read()
#print(info)


output = open('BRO_formatted.txt','w')


url="http://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt"
src = "et_ips"

raw_data = urllib.request.urlopen(url)

data = list ( set ( raw_data.read().decode('utf-8').splitlines() ) )

#meta_desc= desc(data[0])
meta_desc="IP"

for intel in data:
    line=[]
    line.append(intel)
    
    if re.search('[a-zA-Z]', intel):
        line.append("Intel::DOMAIN")
    else:
        line.append("Intel::ADDR")
    line.append(src)
    line.append(meta_desc)
    line.append(url)
    
    output.write("  ".join(line)+'\n')

output.close()






