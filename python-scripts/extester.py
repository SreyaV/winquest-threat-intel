import csv
import urllib.request
from io import BytesIO
from zipfile import ZipFile
from datetime import datetime
import os

log_path = input()
print(log_path)
if not os.path.exists(log_path):
    os.makedirs(log_path)
        
