import time
from datetime import datetime
import json
import os
import random

def form_time_stamp(t):
    ta = datetime.strptime(t, "%d-%m-%Y %H:%M:%S.%f")
    ts = time.mktime(ta.timetuple()) + ta.microsecond / 1000000
    return ts

def formal_timestamp(file1, file2):
    f = open(file1,"r")
    ff = open(file2,"w+")

    lines = f.readlines()
    f.close()
    for l in lines:
        parts = l.split(" ")
        #print(parts)
        ti = parts[0] + " " + parts[1]
        ts = form_time_stamp(ti.replace("Jan", "01"))
        string = str(ts) + " "
        for i in range(2, len(parts)):
            string += parts[i] + " "
        ff.write(string)
    ff.close()

def getpktnumber(line):
    parts = line.split(" ")
    for p in parts:
        if "number[" in p:
            ps = p.split("[")
            pss = ps[1].split("]")
            return int(pss[0])

def getpkttime(line):
    parts = line.split(" ")
    for p in parts:
        if "timestamp[" in p:
            ps = p.split("[")
            pss = ps[1].split("]")
            return float(pss[0])

def getpktttls(line):
    parts = line.split(" ")
    for p in parts:
        if "ttl[" in p:
            ps = p.split("[")
            pss = ps[1].split("]")
            if pss[0] != "NO":
                return int(pss[0])
            else:
                return 0

def getqrytype(line):
    parts = line.split(" ")
    for p in parts:
        if "query_type[" in p:
            ps = p.split("[")
            pss = ps[1].split("]")
            if pss[0] != "NO":
                return int(pss[0])
            else:
                return 0

def getqrypktnum(line):
    parts = line.split(" ")
    for p in parts:
        if "response_to[" in p:
            ps = p.split("[")
            pss = ps[1].split("]")
            if pss[0] != "NO":
                return int(pss[0])
            else:
                return 0

def getcachetime(line):
    parts = line.split(" ")
    for p in parts:
        if "last[" in p:
            ps = p.split("[")
            pss = ps[1].split("]")
            return float(pss[0])

def getresname(line):
    parts = line.split(" ")
    for p in parts:
        if "res[" in p:
            ps = p.split("[")
            pss = ps[1].split("]")
            if pss[0] != "NO":
                return pss[0]
            else:
                return "NO"

def getqueryname(line):
    parts = line.split(" ")
    for p in parts:
        if "query[" in p:
            ps = p.split("[")
            pss = ps[1].split("]")
            if pss[0] != "NO":
                return pss[0]
            else:
                return "NO"

def getfromip(line):
    parts = line.split(" ")
    for p in parts:
        if "from[" in p:
            ps = p.split("[")
            pss = ps[1].split("]")
            if pss[0] != "NO":
                return pss[0]
            else:
                return "NO"

def check_records(file1, file2):
    f = open(file1, "r")
    lines = f.readlines()
    total = len(lines)
    print(total)
    f.close()

    ff = open(file2, "w+")

    for i in range(0, total):
        if "Packet" in lines[i]:
            if len(lines[i])-2 >=0 and lines[i][len(lines[i])-2] == ']':
                if "from [" in lines[i+1]:
                    if len(lines[i+1])-2 >= 0 and lines[i+1][len(lines[i+1])-2] == ']':
                        ff.write(lines[i])
                        ff.write(lines[i+1])
                        ff.write("\n")

    ff.close()

    return "ok"
    #check_records('res/output2.txt', 'res/output_formal.txt')

def get_query_address(line):
    parts = line.split(' ')
    ps = parts[5].split('(')
    addrs = ps[1].split(')')
    addr = addrs[0]
    if addr == parts[7]:
        return addr
    else:
        return "NO"

def get_all_client_queries(file1):
    f = open(file1, "r")
    lines = f.readlines()
    f.close()

    count = 0

    queries = []

    for l in lines:
        if "queries:" in l:
            parts = l.split(' ')
            #print(parts)
            addr = get_query_address(l)
            #print(addr)
            if addr == 'NO':
                break
            count += 1
            q = {'addr':addr, 'type':parts[9], 'time':float(parts[1])}
            queries.append(q)
    print(count)

    #print(queries)
    return queries
#get_all_client_queries('formal_query.log')

def split_date_into_parts(file1, num):
    f = open(file1,'r')
    lines = []
    string = ""
    l = f.readline()
    count = 0
    index = 0
    packets = []
    while True:
        l = f.readline()
        if len(lines) == 0:
            if l == "  {\n":
                lines.append(l)
            else:
                continue
        else:
            lines.append(l)
        if l == "  }\n":
            string = ''.join(lines)
            p = json.loads(string)
            count += 1
            lines = []
            packets.append(p)
        if count == num:
            ff = open("sub/"+str(index)+".json","w+")
            string = json.dumps(packets)
            ff.write(string)
            ff.close()
            packets = []
            print(str(index)+".txt done")
            index += 1
            count = 0

#split_date_into_parts("res/all.pcap",50000)

class packet_loader0:
    def __init__(self, file):
        self.packets = {}
        self.loadpackets(file)

    def loadpackets(self, file):
        f = open(file,'r')
        #print("loadfile",file)
        lines = []
        string = ""
        l = f.readline()
        count = 0
        while True:
            l = f.readline()
            if not l:
                break
            if len(lines) == 0:
                if l == "  {\n":
                    lines.append(l)
                else:
                    continue
            else:
                lines.append(l)
            if l == "  }\n":
                string = ''.join(lines)
                p = json.loads(string)
                count += 1
                lines = []
                #print("load pkt", count)
                self.packets[count] = p

    def get_packet_num(self, num):
        if num in self.packets.keys():
            return self.packets[num]
        else:
            return "NO"

class packet_loader:

    def __init__(self):
        self.packets = {}
        self.bufpackets = {}
        self.file_now = 0
        self.loadpackets(0)
        self.file_buf = -1
        
    def loadpackets(self, num):
        with open("sub/"+str(num)+".json") as f:
            packets_json = json.load(f)
            f.close()
        count = 0
        self.packets = {}
        for p in packets_json:
            count += 1
            self.packets[count] = p
        self.file_now = num

    def loadbufpackets(self, num):
        with open("sub/"+str(num)+".json") as f:
            packets_json = json.load(f)
            f.close()
        count = 0
        self.bufpackets = {}
        for p in packets_json:
            count += 1
            self.bufpackets[count] = p
        self.file_buf = num

    def get_packet_num(self, num, log=""):
        fileindex = int((num-1) / 50000)

        ind = num - fileindex * 50000

        if fileindex == self.file_now:
            return self.packets[ind]
        else:
            print("seeker readfile:",fileindex)
            self.loadpackets(fileindex)
            return self.packets[ind]
        
        # if fileindex == self.file_buf:
        #     return self.bufpackets[ind]
        
        # if fileindex > self.file_now:
        #     self.bufpackets = self.packets
        #     self.file_buf = self.file_now
        #     self.loadpackets(fileindex)
        #     return self.packets[ind]
        
        # if fileindex < self.file_buf:
        #     self.packets = self.bufpackets
        #     self.file_now = self.file_buf
        #     self.loadbufpackets(fileindex)
        #     return self.bufpackets[ind]


class packet_loader2:

    def __init__(self):
        self.packets = []
        for i in range(0,5):
            temp = {}
            self.packets.append(temp)
        self.file_now = 0
        for i in range(0,5):
            self.loadpackets(i, False)
        
    def loadpackets(self, num, first, dire=0):
        fileindex = self.file_now + num
        if first == False:
            print("loader readfile:",fileindex)
            with open("sub/"+str(fileindex)+".json") as f:
                packets_json = json.load(f)
                f.close()
            count = 0
            self.packets[num] = {}
            for p in packets_json:
                count += 1
                self.packets[num][count] = p
        else:
            self.packets[num] = self.packets[num+dire]


    def get_packet_num(self, num, log=""):
        fileindex = int((num-1) / 50000)
        #print("load pkt:",num,fileindex)

        if fileindex >= self.file_now and fileindex <= self.file_now + 4:
            ind = num - fileindex * 50000
            return self.packets[fileindex - self.file_now][ind]
        else:
            if fileindex > self.file_now + 4:
                if fileindex - (self.file_now + 4) == 1:
                    self.file_now += 1
                    for i in range(0,4):
                        self.loadpackets(i, True, 1)
                    self.loadpackets(4, False)
                else:
                    self.file_now = fileindex - 4
                    for i in range(0, 5):
                        self.loadpackets(i, False)
            else:
                if fileindex == self.file_now - 1:
                    self.file_now -= 1
                    for i in range(1,5):
                        self.loadpackets(5-i, True, -1)
                    self.loadpackets(0, False)
                else:
                    self.file_now = fileindex
                    for i in range(0, 5):
                        self.loadpackets(i, False)
            ind = num - fileindex * 50000
            return self.packets[fileindex - self.file_now][ind]

class root_servers:

    def __init__(self):
        f = open("rootserverlist.txt")
        lines = f.readlines()
        self.list = []
        for l in lines:
            self.list.append(l.replace("\n",""))
        #print(self.list)
        f.close()
    def testrootserver(self, addr):
        if addr in self.list:
            return True
        else:
            return False

class top_servers:

    def __init__(self):
        f = open("topserverlist.txt")
        lines = f.readlines()
        self.list = []
        for l in lines:
            self.list.append(l.replace("\n",""))
        print(self.list)
        f.close()
    def testtopserver(self, addr):
        if addr in self.list:
            return True
        else:
            return False

class banner:

    def __init__(self):
        f = open("query_ns.json")
        self.nss = {}
        self.nss = json.load(f)
        f.close()

    def banlist(self, query):
        if query in self.nss.keys():
            return self.nss[query].keys()
        else:
            return []

    def ban(self, ip, rate=1):
        rand = random.random()
        if rand >= rate:
            os.system("sudo iptables -A INPUT -s "+ip+" -j DROP")

    def banall(self,query):
        lis = self.banlist(query)
        for ip in lis:
            self.ban(ip,0)

    def clean(self):
        os.system("sudo iptables -F")

def count_redundant_root_query():
    f = open('res/red.txt')
    lines = f.readlines()
    f.close()
    PL = root_servers()
    count = 0
    for l in lines:
        fromip = getfromip(l)
        if PL.testrootserver(fromip):
            count += 1
    print(count)

#count_redundant_root_query()