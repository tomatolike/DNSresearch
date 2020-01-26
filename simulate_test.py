import time
import sys
import os
import threading
import random
from tools import *
import socket

thread_pool = threading.Semaphore(value=50)

def query_ipv4(host,num):
    print("Query[%d]:%s Ver:4"%(num,host))
    try:
        socket.gethostbyname(host)
    except:
        ok = 1
        # do nothing
    thread_pool.release()
    sys.exit()

def query_ipv6(host,num):
    print("Query[%d]:%s Ver:6"%(num,host))
    try:
        socket.getaddrinfo(host, None, socket.AF_INET6)
    except:
        ok = 1
        # do nothing
    thread_pool.release()
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
    thread_pool.acquire()
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
        print("stop")
        time.sleep(5)

