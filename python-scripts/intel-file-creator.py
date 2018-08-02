import csv
import urllib.request
from io import BytesIO
from zipfile import ZipFile
from datetime import datetime


sources = open('sources.txt', 'r')
info = sources.read().splitlines()
#print(info)
output = open('formatted-intel.txt','w')

print(str(datetime.now()))

for source in info:
    source=source.split()
    if (source[0].upper() in ['SNORT', 'TALOS', 'ET_IPS']) or (source[0] == 'Abuse'):
        raw_data = urllib.request.urlopen(source[1])

        data = list ( set ( raw_data.read().decode('utf-8').splitlines() ) )
        for r in data:
            if r[0]!='#':
                output.write('\t'.join(source) + '\t' + r + '\t' + '-' + '\n')
    
    elif source[0] == 'abuse':
        raw_data = urllib.request.urlopen(source[1])

        data = raw_data.read().decode('utf-8').splitlines()
        for r in data:
            if r[0]!='#':
                intel = r[r.find(',')+1: ].split(',')
                output.write('\t'.join(source) + '\t' + intel[0] + '\t' + intel[1] + '\n')

    elif source[0] == 'Blacklist':
        url=urllib.request.urlopen(source[1])
        with ZipFile(BytesIO(url.read())) as my_zip_file:
            for contained_file in my_zip_file.namelist():
                # with open(("unzipped_and_read_" + contained_file + ".file"), "wb") as output:
                for line in my_zip_file.open(contained_file).readlines():
                    d_line = line.decode('utf-8')
                    d_line=d_line.replace('\n','')
                    output.write('\t'.join(source) + '\t' + d_line + '\t' + '-' + '\n')
                    #links_test.write(d_line)

print(str(datetime.now()))

output.close()




