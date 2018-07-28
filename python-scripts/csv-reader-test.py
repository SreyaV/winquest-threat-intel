import csv
import urllib.request
import urllib


csvtest = open('csv-test.txt', 'w')

raw_data = urllib.request.urlopen('https://sslbl.abuse.ch/blacklist/sslblacklist.csv')

reader = raw_data.read().decode('utf-8').splitlines()
for r in reader:
    if r[0]!='#':
        csvtest.write(r[r.find(',')+1: ].replace(',','  ') + '\n')

#data=[r for r in reader]

#print(data)
csvtest.close()

##csvtest2 = open('csv-test2.txt', 'w')
##
##url = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
##
##filename = url.split('/')[-1]
##with open(filename, 'wb') as out_file:
##    out_file.write(requests.get(url).content)
##
### _csv.Error: iterator should return strings, not bytes (did you open the file in text mode?)
### change 'rb' to 'r'
##with open(filename, 'r') as in_file:
##    for row in csv.reader(in_file):
##        csvtest2.write(" ".join(data))
##
##        
##csvtest2.close()
##	
