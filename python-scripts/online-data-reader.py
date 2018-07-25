import urllib.request

url="http://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt"

##wp = urllib.request.urlopen(url)
##pw = wp.read()
##pw=str(pw)
##a = "safsdafs\nsdfa"
###npw=pw.split()
##print(pw)


data = urllib.request.urlopen(url)

d = data.read().decode('utf-8').splitlines()

print(d)



#for line in data: # files are iterable
#    print (line)
