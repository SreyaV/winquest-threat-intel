#Necessary Imports
import csv
import urllib.request
from io import BytesIO
from zipfile import ZipFile
from datetime import datetime



##def get_metaurl(src_name, raw_src_info):
##    for line in raw_src_info:
##        line=line.split()
##        if src_name == line[0]:
##            for r in line:
##                if 'http' in r:
##                    return r
##    return '-'


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
        
#######################################################

def bro_generator(newpath):
    #Necessary Files
    
    errors=[]
    
    try:
        sources = open('sources.txt', 'r')  #Note: this contains direct links to the intel files from each source
    except FileNotFoundError:
        errors.append("sources.txt does not exist")
        return 0

##    try:
##        raw_sources = open('raw-sources.txt', 'r')  #Note: this contains the original, umbrella URLs for each source
##    except FileNotFoundError:
##        errors.append("raw-sources.txt does not exist")
##        return 0

    output = open(newpath + '/formatted-intel.txt','w') 
    error_log = open(newpath + '/errors-log.txt','w')
    repeats_log = open(newpath + '/repeats-log.txt','w')

    intel_type = {'IP' : '::ADDR' , 'DOMAINS' : '::DOMAIN' , 'URLS' : 'URL' , 'SHA-1' : '::CERT_HASH', 'DNS' : 'DOMAINS'}  #for indicator_type
    src_info = sources.read().splitlines()  #for meta.source
##    raw_src_info = raw_sources.read().splitlines()  #for meta.url


    counter = 0
    ips = set([])
    domains = set([])
    urls = set([])
    sha1 = set ([]) 
    repeats=[]

    
    for source in src_info:

        try:
        
            if source !="" and source[0]!= '#':

                source=source.split()

        ##############
                
                if (source[0].upper() in ['SNORT', 'TALOS', 'ET_IPS', 'MALIPS', 'CIARMY', 'MALHOSTS']) or (source[0] == 'Abuse'):
                    try:
                        raw_data = urllib.request.urlopen(source[1])
                    except:
                        errors.append(source[0]+ " does not have a valid link to intel")

                    try:    
                        data = raw_data.read().decode('utf-8').splitlines()
                    except:
                        errors.append(source[0]+ " does not link directly to the intel file")
                        data=[]
                    for r in data:
                        try:
                            if r != "" and r[0]!='#':
                                if source[0].upper() == 'MALHOSTS':
                                    r = r.split()[-1]
                                if r!= 'localhost':
                                    if check_repeats(r, source[2].upper(), ips, domains, urls, sha1):
                                        line = [r, intel_type[source[2].upper()], source[0],  '-', source[1]]
                                        counter = counter+1
                                        output.write ('    '.join(line)+ '\n')
                                    else:
                                        repeats.append(r)
                        except:
                            errors.append(source[0] + " contains invalid intel")
        
        ################
                
                elif source[0] == 'abuse':
                    try:
                        raw_data = urllib.request.urlopen(source[1])
                    except:
                        errors.append(source[0]+ " does not have a valid link to intel")

                    try:    
                        data = raw_data.read().decode('utf-8').splitlines()
                    except:
                        errors.append(source[0]+ " does not link directly to the intel file")
                        data=[]
                        
                    
                    for r in data:
                        try:                
                            if r[0]!='#':
                                intel = r[r.find(',')+1: ].split(',')
                                if check_repeats(intel[0], source[2].upper(), ips, domains, urls, sha1):
                                    line = [intel[0], intel_type[source[2].upper()], source[0], intel[1], source[1]]
                                    counter = counter+1
                                    output.write ('    '.join(line) + '\n' )
                                else:
                                    repeats.append(intel[0])
                        
                        except:
                            errors.append(source[0] + " contains invalid intel")

        ####################            

                elif source[0] == 'Blacklist':
                    try:
                        raw_data = urllib.request.urlopen(source[1])
                    except:
                        errors.append(source[0]+ " does not have a valid link to intel")

                    try:
                        with ZipFile(BytesIO(raw_data.read())) as my_zip_file:
                            for contained_file in my_zip_file.namelist():
                                # with open(("unzipped_and_read_" + contained_file + ".file"), "wb") as output:
                                for line in my_zip_file.open(contained_file).readlines():
                                    try:
                                        d_line = line.decode('utf-8')
                                        d_line=d_line.replace('\n','')
                                        
                                        if check_repeats(d_line, source[2].upper(), ips, domains, urls, sha1):
                                            line = [d_line, intel_type[source[2].upper()], source[0],  '-', source[1]]
                                            counter = counter+1
                                            output.write ('    '.join(line) + '\n')
                                        else:
                                            repeats.append(d_line)
                                    except:
                                        errors.append(source[0] + " contains invalid intel")
                    except:
                        errors.append(source[0]+ " does not link directly to the intel file")

        ############################

                elif source[0].upper() in ['BOTCC', 'TOR']:
                    try:
                        raw_data = urllib.request.urlopen(source[1])
                    except:
                        errors.append(source[0]+ " does not have a valid link to intel")

                    try:    
                        data = raw_data.read().decode('utf-8').splitlines()
                    except:
                        errors.append(source[0]+ " does not link directly to the intel file")
                        data=[]
                        
                    
                    for r in data:
                        try:                
                            if r != "" and r[0]!='#':
                                addresses = r[r.find('[')+1: r.find(']')].split(',')
                                if 'msg' in r:
                                    msg = r[r.find('msg')+5: r.find(';')-1]
                                else:
                                    msg = "-"
                                    
                                for address in addresses:
                                    if check_repeats(address, source[2].upper(), ips, domains, urls, sha1):
                                        line = [address, intel_type[source[2].upper()], source[0], msg, source[1]]
                                        counter = counter+1
                                        output.write ('    '.join(line) + '\n' )
                                    else:
                                        repeats.append(address)
                        
                        except:
                            errors.append(source[0] + " contains invalid intel")

        ######################

                elif source[0].upper() == 'ALIENVAULT':
                    try:
                        raw_data = urllib.request.urlopen(source[1])
                    except:
                        errors.append(source[0]+ " does not have a valid link to intel")

                    try:    
                        data = raw_data.read().decode('utf-8').splitlines()
                    except:
                        errors.append(source[0]+ " does not link directly to the intel file")
                        data=[]
                        
                    
                    for r in data:
                        try:                
                            if r!= "" and r[0]!='#':
                                intel = r.split(" # ")
                                if check_repeats(intel[0], source[2].upper(), ips, domains, urls, sha1):
                                    line = [intel[0], intel_type[source[2].upper()], source[0], intel[1], source[1]]
                                    counter = counter+1
                                    output.write ('    '.join(line) + '\n' )
                                else:
                                    repeats.append(intel[0])
                        
                        except:
                            errors.append(source[0] + " contains invalid intel")    

        except:
            errors.append('Unknown error in ' + source)
        
    output.close()
    repeats_log.write("Repeated intel: \n" + '\n'.join(repeats))
    repeats_log.close()
    error_log.write("Errors encountered: \n" + '\n'.join(errors))
    error_log.close()
    return counter





    

