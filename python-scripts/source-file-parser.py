sources = open('raw-sources.txt', 'r')
info = sources.read()

sources.close()

info = info.split()

#print("\n".join(info))

#print()

src = []
url = []
itype = []

i=0
while i<len(info):
    if info[i]=='&':
        info[i-1:i+2]=[''.join(info[i-1:i+2])]
    i=i+1

#print(len(info))

i=0
while i<len(info)-2:
    info[i+2]=info[i+2].replace('(','').replace(')','')
    for elem in info[i+2].split('&'):
        src.append(info[i])
        url.append(info[i+1])        
        itype.append(elem)
    i=i+3

##print(src)
##
##print()
##
##print(url)
##print()
##print(itype)
##
##print()

formatted_sources=open('sources.txt', 'w')
for i in range (0,len(src)):
    print(src[i] + '    ' + url[i] + '    ' + itype[i])
    formatted_sources.write(src[i] + '    ' + url[i] + '    ' + itype[i] + '\n')

formatted_sources.close()
#print("\n".join(info))
#print(url)
#print(itype)
