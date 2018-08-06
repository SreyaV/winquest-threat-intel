#Necessary Imports
import csv
import urllib.request
from io import BytesIO
from zipfile import ZipFile
from datetime import datetime



def get_metaurl(src_name, raw_src_info):
    for line in raw_src_info:
        line=line.split()
        if src_name == line[0]:
            for r in line:
                if 'http' in r:
                    return r
    return '-'


def check_repeats(intel, i_type, ips, domains, urls, sha1):
    if i_type == 'IP':
        length = len(ips)
        ips.add(intel)
        if len(ips)> length:
            return True
        else:
            return False
    elif i_type == 'DOMAINS':
        length = len(domains)
        domains.add(intel)
        if len(domains) > length:
            return True
        else:
            return False
    elif i_type == 'URLS':
        length = len(urls)
        urls.add(intel)
        if len(urls) > length:
            return True
        else:
            return False
    elif i_type == 'SHA-1':
        length = len(sha1)
        sha1.add(intel)
        if len(sha1) > length:
            return True
        else:
            return False
    else:
        return True
        

def bro_generator(newpath):
    #Necessary Files
    sources = open('sources.txt', 'r')  #Note: this contains direct links to the intel files from each source
    raw_sources = open('raw-sources.txt', 'r')  #Note: this contains the original, umbrella URLs for each source
    
    output = open(newpath + '/formatted-intel.txt','w') 
    

    intel_type = {'IP' : '::ADDR' , 'DOMAINS' : '::DOMAIN' , 'URLS' : 'URL' , 'SHA-1' : '::CERT_HASH'}  #for indicator_type
    src_info = sources.read().splitlines()  #for meta.source
    raw_src_info = raw_sources.read().splitlines()  #for meta.url


    counter = 0
    ips = set([])
    domains = set([])
    urls = set([])
    sha1 = set ([])

    print('check1')
    
    repeats=[]
    for source in src_info:
        source=source.split()
        if (source[0].upper() in ['SNORT', 'TALOS', 'ET_IPS']) or (source[0] == 'Abuse'):

            print('check2')
            
            raw_data = urllib.request.urlopen(source[1])
            data = list  ( raw_data.read().decode('utf-8').splitlines() ) 
            
            for r in data:
                if r[0]!='#':
                    if check_repeats(r, source[2].upper(), ips, domains, urls, sha1):
                        line = [r, intel_type[source[2].upper()], source[0],  '-', get_metaurl(source[0], raw_src_info)]
                        counter = counter+1
                        output.write ('\t'.join(line)+ '\n')
                    else:
                        repeats.append(r)

        
        elif source[0] == 'abuse':

            print('check3')
            
            raw_data = urllib.request.urlopen(source[1])

            data = raw_data.read().decode('utf-8').splitlines()
            for r in data:
                if r[0]!='#':
                    
                    intel = r[r.find(',')+1: ].split(',')
                    
                    if check_repeats(intel[0], source[2].upper(), ips, domains, urls, sha1):
                        line = [intel[0], intel_type[source[2].upper()], source[0], intel[1], get_metaurl(source[0], raw_src_info)]
                        counter = counter+1
                        output.write ('\t'.join(line) + '\n' )
                    else:
                        repeats.append(intel[0])


            

        elif source[0] == 'Blacklist':

            print('check4')
            
            raw_data=urllib.request.urlopen(source[1])
            with ZipFile(BytesIO(raw_data.read())) as my_zip_file:
                for contained_file in my_zip_file.namelist():
                    # with open(("unzipped_and_read_" + contained_file + ".file"), "wb") as output:
                    for line in my_zip_file.open(contained_file).readlines():
                        #print('check5')
                        d_line = line.decode('utf-8')
                        d_line=d_line.replace('\n','')
                        
                        if check_repeats(d_line, source[2].upper(), ips, domains, urls, sha1):
                            line = [d_line, intel_type[source[2].upper()], source[0],  '-', get_metaurl(source[0], raw_src_info)]
                            counter = counter+1
                            output.write ('\t'.join(line) + '\n')
                        else:
                            repeats.append(d_line)
    
    #print(str(datetime.now()))
    output.close()
    repeats.append(str(counter))
    return repeats





    

