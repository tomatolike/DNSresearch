import time
import sys
import os
import threading
import random
from tools import *
import socket
import datetime
def query_ipv4(host,num):
    print("Query[%d]:%s Ver:4"%(num,host))
    try:
        socket.gethostbyname(host)
    except:
        ok = 1
        # do nothing
    sys.exit()

def query_ipv6(host,num):
    print("Query[%d]:%s Ver:6"%(num,host))
    try:
        socket.getaddrinfo(host, None, socket.AF_INET6)
    except:
        ok = 1
        # do nothing
    sys.exit()

queries = get_all_client_queries('formal_query.log')
total = len(queries)
print(total)

i = 0

counter = 0

threads = []

while True:
    q = queries[int(random.random()*9677)]
    #s = 'https://www.baidu.com'
    if q['type'] == 'A':
        newthread = threading.Thread(target=query_ipv4, args=(q['addr'], counter, ))
        newthread.start()
        threads.append(newthread)
    elif q['type'] == 'AAAA':
        newthread = threading.Thread(target=query_ipv6, args=(q['addr'], counter, ))
        newthread.start()
        threads.append(newthread)
    #break
    counter += 1
    if counter % 50 == 0:
        for thread in threads:
            thread.join()
        ts = datetime.datetime.now()
        print("stop",ts.strftime("%Y.%m.%d-%H:%M:%S"))
        time.sleep(5)
    else:
        time.sleep(random.random()*0.5)

