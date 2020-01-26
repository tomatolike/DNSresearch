import time
from datetime import datetime

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

    #print(queries)
    return queries
    #get_all_client_queries('res/formal_query.log')

