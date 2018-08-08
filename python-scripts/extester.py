import csv
import urllib.request
from io import BytesIO
from zipfile import ZipFile
from datetime import datetime
import os

raw_data = urllib.request.urlopen('http://www.malwaredomainlist.com/hostslist/hosts.txt')
data = raw_data.read().decode('utf-8').splitlines() 
for r in data:
    if r!= "" and r[0]!= "#":
        print(r.split()[-1])
        
