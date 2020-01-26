import socket
import time
import sys
import os
import threading
from tools import *

def query_ipv4(host,num):
    print("Query[%d]:%s Ver:4"%(num,host))
    try:
        socket.gethostbyname(host)
    except:
        exit(0)
        # do nothing

def query_ipv6(host,num):
    print("Query[%d]:%s Ver:6"%(num,host))
    try:
        socket.getaddrinfo(host, None, socket.AF_INET6)
    except:
        exit(0)
        # do nothing

queries = get_all_client_queries('formal_query.log')
total = len(queries)

base_time = queries[0]['time'] - 10
real_base_time = time.time()

print(base_time, real_base_time)

i = 0

while(True):
    if queries[i]['time'] - base_time <= time.time() - real_base_time:
        if queries[i]['type'] == 'A':
            newthread = threading.Thread(target=query_ipv4, args=(queries[i]['addr'], i, ))
            newthread.start()
        elif queries[i]['type'] == 'AAAA':
            newthread = threading.Thread(target=query_ipv6, args=(queries[i]['addr'], i, ))
            newthread.start()
        else:
            print("Wrong Query")
        i += 1
        if (queries[i]['time'] - base_time) - (time.time() - real_base_time) >= 5:
            time.sleep((queries[i]['time'] - base_time) - (time.time() - real_base_time) - 2)
    
