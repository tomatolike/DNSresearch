from tools import *
import sys
import time
import socket

f = open("query_list.txt")
lines = f.readlines()
f.close()

BN = banner()

latency = []

rate = float(sys.argv[1])

for l in lines:
    query = l.replace('\n','')
    banlist = BN.banlist(query)
    for ip in banlist:
        BN.ban(ip,rate)

    timestart = time.time()
    try:
        socket.gethostbyname(query)
        timeend = time.time()
    except:
        timeend = time.time()

    duration = timeend - timestart

    latency.append(duration)

    BN.clean()
