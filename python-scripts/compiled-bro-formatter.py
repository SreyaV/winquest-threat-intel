
#Necessary Imports
import csv
import urllib.request
from io import BytesIO
from zipfile import ZipFile
from datetime import datetime
import os


def get_metaurl(src_name, raw_src_info):
    for line in raw_src_info:
        line=line.split()
        if src_name == line[0]:
            for r in line:
                if 'http' in r:
                    return r
    return '-'


def main():
    #Necessary Files
    today = datetime.today().strftime('%Y-%m-%d')
    sources = open('sources.txt', 'r')  #Note: this contains direct links to the intel files from each source
    raw_sources = open('raw-sources.txt', 'r')  #Note: this contains the original, umbrella URLs for each source
    newpath = r"C:/Users/Sreya Vangara/Documents/winquest-threat-intel/python-scripts/Logs/" + "WCIQ-" + today
    if not os.path.exists(newpath):
        os.makedirs(newpath)
    output = open(newpath + '/formatted-intel.txt','w') 

    print("hi")

    intel_type = {'IP' : '::ADDR' , 'DOMAINS' : '::DOMAIN' , 'URLS' : 'URL' , 'SHA-1' : '::CERT_HASH'}  #for indicator_type
    src_info = sources.read().splitlines()  #for meta.source
    raw_src_info = raw_sources.read().splitlines()  #for meta.url

    #print(str(datetime.now()))

    for source in src_info:
        source=source.split()
        if (source[0].upper() in ['SNORT', 'TALOS', 'ET_IPS']) or (source[0] == 'Abuse'):
            raw_data = urllib.request.urlopen(source[1])
            data = list ( set ( raw_data.read().decode('utf-8').splitlines() ) )
            
            for r in data:
                if r[0]!='#':
                    line = [r, intel_type[source[2].upper()], source[0],  '-', get_metaurl(source[0], raw_src_info)]


        
        elif source[0] == 'abuse':
            raw_data = urllib.request.urlopen(source[1])

            data = raw_data.read().decode('utf-8').splitlines()
            for r in data:
                if r[0]!='#':
                    intel = r[r.find(',')+1: ].split(',')
                    line = [r[0], intel_type[source[2].upper()], source[0], r[1], get_metaurl(source[0], raw_src_info)]



        elif source[0] == 'Blacklist':
            raw_data=urllib.request.urlopen(source[1])
            with ZipFile(BytesIO(raw_data.read())) as my_zip_file:
                for contained_file in my_zip_file.namelist():
                    # with open(("unzipped_and_read_" + contained_file + ".file"), "wb") as output:
                    for line in my_zip_file.open(contained_file).readlines():
                        d_line = line.decode('utf-8')
                        d_line=d_line.replace('\n','')
                        line = [d_line, intel_type[source[2].upper()], source[0],  '-', get_metaurl(source[0], raw_src_info)]



    print(str(datetime.now()))

    output.close()


main()
    

