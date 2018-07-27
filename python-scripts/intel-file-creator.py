import csv
import urllib.request


sources = open('sources.txt', 'r')
info = sources.read().splitlines()
#print(info)
output = open('BRO_formatted.txt','w')

for source in info:
    source=source.split()
    print(source[1])
    print()
    if source[0].upper() in ['SNORT', 'TALOS', 'ET_IPS']:
        raw_data = urllib.request.urlopen(source[1])

        data = list ( set ( raw_data.read().decode('utf-8').splitlines() ) )
        print (data)
    
    elif source[0] == 'abuse':
        raw_data = urllib.request.urlopen(source[1], 'rt')
        reader = csv.reader(raw_data)
        data= [ r for r in reader]
        data.pop(0)
        print(data)


##    try:
##        #print(source)
##        details = source.split('    ')
##        #print(details)
##        url=details[1]
##        src = details[0]
##
##        raw_data = urllib.request.urlopen(url)
##
##        data = list ( set ( raw_data.read().decode('utf-8').splitlines() ) )


