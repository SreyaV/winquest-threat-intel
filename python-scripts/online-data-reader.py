import urllib.request
import re

sources = open('sources.txt', 'r')
info = sources.read().splitlines()

output = open('BRO_formatted.txt','w')

for source in info:
    try:
        #print(source)
        details = source.split('    ')
        #print(details)
        url=details[1]
        src = details[0]

        raw_data = urllib.request.urlopen(url)

        data = list ( set ( raw_data.read().decode('utf-8').splitlines() ) )

        #meta_desc= desc(data[0])
        meta_desc=details[2]

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
            
    except:
        print(source + " didn't work")

output.close()






