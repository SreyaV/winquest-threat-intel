import csv
import urllib.request


sources = open('sources.txt', 'r')
info = sources.read().splitlines()
#print(info)
output = open('formatted-intel.txt','w')

for source in info:
    source=source.split()
    if source[0].upper() in ['SNORT', 'TALOS', 'ET_IPS']:
        raw_data = urllib.request.urlopen(source[1])

        data = list ( set ( raw_data.read().decode('utf-8').splitlines() ) )
        for r in data:
            output.write('    '.join(source) + '    '+r+ '    ' + '-' + '\n')
    
    elif source[0] == 'abuse':
        raw_data = urllib.request.urlopen('https://sslbl.abuse.ch/blacklist/sslblacklist.csv')

        data = raw_data.read().decode('utf-8').splitlines()
        for r in data:
            if r[0]!='#':
                output.write('    '.join(source) + '    ' + r[r.find(',')+1: ].replace(',','    ') + '\n')

output.close()




