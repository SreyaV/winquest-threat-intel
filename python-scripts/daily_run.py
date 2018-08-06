import broformattertest
import time
import os
from datetime import datetime


start_time = time.clock()

today = datetime.today().strftime('%Y-%m-%d')
newpath = r"C:/Users/Sreya Vangara/Documents/winquest-threat-intel/python-scripts/Logs/" + "WCIQ-" + today
if not os.path.exists(newpath):
    os.makedirs(newpath)

log = open(newpath + '/log.txt','w')

log.write("Start Time: "+ str(datetime.now()) + '\n')

repeats = broformattertest.bro_generator(newpath)

log.write("End Time: "+ str(datetime.now()) + '\n')
log.write("Total time taken: " + str(time.clock() - start_time) + " seconds\n")
log.write("Total intel items processed: "+ repeats[-1] + '\n')
log.write("Redundant intel: " + '\n' + '\n'.join(repeats[ :-1]))
log.close()

#input()
