from tools import *
import sys

filename = sys.argv[1]

Loader = packet_loader0("res/"+filename+".json")

RS = root_servers()

TS = top_servers()

BN = banner()

f = open("query_time.txt")
lines = f.readlines()
f.close()

pkt_num = 0

succ = 0
count = 0
blocked = 0
succ_block = 0

blocking_list = []
meets = 0

suc_names = []

for l in lines:
    parts = l.split(" ")
    real_query = parts[0]
    time = float(parts[1])

    ### Try to find the start pkt
    ok = False
    while True:
        pkt_num += 1

        packet = Loader.get_packet_num(pkt_num)

        if packet == "NO":
            break

        if float(packet['_source']['layers']['frame']['frame.time_epoch']) > time + 20:
            pkt_num -= 1
            break

        if not TS.testtopserver(packet['_source']['layers']['ip']['ip.dst']):
            continue

        try:
            dnslayer = packet['_source']['layers']['dns']
            if dnslayer['dns.flags_tree']['dns.flags.response'] == '1' or dnslayer['dns.flags_tree']['dns.flags.truncated'] == '1':
                continue
            for key in dnslayer['Queries'].keys():
                if dnslayer['Queries'][key]['dns.qry.name'] == real_query and ( dnslayer['Queries'][key]['dns.qry.type']=='1' or dnslayer['Queries'][key]['dns.qry.type']=='28'):
                    ok = True
        except:
            pass
        if not ok:
            continue
        else:
            break
    if not ok:
        continue
    count += 1
    print("Query:",real_query,pkt_num)
    ### Try to find the ns
    ok = False
    temp_cache = {}
    check_list = []
    back_list = {}
    while True:
        pkt_num += 1

        packet = Loader.get_packet_num(pkt_num)

        if packet == "NO":
            break

        if float(packet['_source']['layers']['frame']['frame.time_epoch']) > time + 20:
            pkt_num -= 1
            break

        try:
            dnslayer = packet['_source']['layers']['dns']
            temp_ok = False
            if dnslayer['dns.flags_tree']['dns.flags.response'] != '1' or dnslayer['dns.flags_tree']['dns.flags.truncated'] == '1':
                continue
            for key in dnslayer['Queries'].keys():
                if dnslayer['Queries'][key]['dns.qry.name'] == real_query:
                    temp_ok = True

            if temp_ok:
                nsrecord = dnslayer['Additional records']
                nskeys = nsrecord.keys()
                for k in nskeys:
                    if 'dns.aaaa' in nsrecord[k].keys():
                        temp_cache[nsrecord[k]['dns.aaaa']] = nsrecord[k]['dns.resp.name']
                        check_list.append(nsrecord[k]['dns.resp.name'])
                    if 'dns.a' in nsrecord[k].keys():
                        temp_cache[nsrecord[k]['dns.a']] = nsrecord[k]['dns.resp.name']
                        check_list.append(nsrecord[k]['dns.resp.name'])
                
                nss = dnslayer['Authoritative nameservers']
                nsnames = nss.keys()
                for k in nsnames:
                    if 'dns.ns' in nss[k].keys():
                        back_list[nss[k]['dns.ns']] = 0
                ok = True
                
        except:
            pass

        if ok:
            break
    
    #print(back_list.keys(), check_list)
    # for key in back_list.keys():
    #     if key not in check_list:
    #         ok = False
    #         break
    
    if not ok:
        continue

    print("NSs:",pkt_num)
    ### Try to find the redundant queries
    ok = False
    if_blocked = True
    not_blocked_num = 0
    while True:
        pkt_num += 1

        packet = Loader.get_packet_num(pkt_num)

        if packet == "NO":
            break

        if float(packet['_source']['layers']['frame']['frame.time_epoch']) > time + 20:
            pkt_num -= 1
            break

        # if packet['_source']['layers']['ip']['ip.src'] in temp_cache.keys() or packet['_source']['layers']['ip']['ip.dst'] in temp_cache.keys():
        #     if_blocked = False
        #     not_blocked_num = pkt_num
        #     continue

        

        try:
            dnslayer = packet['_source']['layers']['dns']

            for key in dnslayer['Queries'].keys():
                if dnslayer['Queries'][key]['dns.qry.name'] == real_query:
                    if int(dnslayer['dns.count.answers']) > 0:
                        if_blocked = False
                        not_blocked_num = pkt_num
                        break

            if not RS.testrootserver(packet['_source']['layers']['ip']['ip.dst']):
                continue
            for key in dnslayer['Queries'].keys():
                if dnslayer['Queries'][key]['dns.qry.name'] in back_list.keys():
                    ok = True
        except:
            pass

        if ok:
            break

    if ok:
        succ += 1

    if_firstmeet = False
    for key in back_list.keys():
        if key not in blocking_list:
            if_firstmeet = True

    if if_blocked:
        blocked += 1
        if ok:
            succ_block += 1
            if len(BN.banlist(real_query)) > 0:
                suc_names.append(real_query)

    if if_blocked:
        for key in back_list.keys():
            blocking_list.append(key)

    if not ok and if_blocked and not if_firstmeet:
        meets += 1

    print("Succ:",ok,pkt_num," Block:",if_blocked, not_blocked_num, pkt_num, if_firstmeet)


    

print(count, succ, blocked, succ_block, meets)

ft = open("query_list.txt","w+")
for name in suc_names:
    ft.write(name+"\n")
ft.close()