def getpktnumber(line):
    parts = line.split(" ")
    p1 = parts[0].split(":")
    number = int(p1[1])
    return number

def getpkttime(line):
    parts = line.split(" ")
    time = float(parts[1])
    return time

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
    return float(parts[1])

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

f = open("output.txt","r")

cache = {0:1.0}
ttls = {0:0}

lines = f.readlines()

count = 0

for l in lines:
    count += 1
    

index = 0

red_count = 0
pre_count = 0

while True:
    if "Packet" in lines[index]:
        cache[getpktnumber(lines[index])] = getpkttime(lines[index])

    if "ttl" in lines[index]:
        ttls[getpkttime(lines[index-1])] = getpktttls(lines[index])

    if "REDUNDANT" in lines[index]:
        red_count += 1
        query_num = getqrypktnum(lines[index-1])
        query_time = cache[query_num]
        cache_time = getcachetime(lines[index])
        ttl_time = ttls[cache_time]
        res_name = getresname(lines[index-1])
        print(cache_time, ttl_time, query_time, res_name)
        if cache_time + ttl_time < query_time + 2:
            pre_count += 1

    index += 1
    if index == count:
        break

print(red_count, pre_count)