from datetime import datetime

from io import BytesIO
from zipfile import ZipFile
import urllib.request
links_test = open('Blacklist-ips.txt','w')
print(str(datetime.now()))
url = urllib.request.urlopen("https://github.com/mitchellkrogza/Ultimate.Hosts.Blacklist/blob/master/ips.list.zip?raw=true")
i = 0
with ZipFile(BytesIO(url.read())) as my_zip_file:
    for contained_file in my_zip_file.namelist():
        # with open(("unzipped_and_read_" + contained_file + ".file"), "wb") as output:
        print(str(datetime.now()))
        for line in my_zip_file.open(contained_file).readlines():
            d_line = line.decode('utf-8')
            if i>-1:
                links_test.write(d_line)
            i=i+1

links_test.close()
