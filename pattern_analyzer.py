from tools import *

# Start analyzing 
## Read real-time analyze result:
f = open('res/simple.txt')
lines = f.readlines()
f.close()


## Go through all lines and find Redundant [com]
redundant_count = 0
succ = 0
i = 0
Loader = packet_loader()
badf = open("analyze_res.txt","w+")
times = []

for i in range(0,len(lines)):
    if "Redundant[" in lines[i] and "name[com]" in lines[i]:
        ### Found a redundant name[com]
        # if redundant_count > 0:
        #     break
        redundant_count += 1
        ### Find out which ns it is querying
        ns = getqueryname(lines[i-1])
        red_res_num = getpktnumber(lines[i-2])
        red_qur_num = getqrypktnum(lines[i-1])

        qry_type = getqrytype(lines[i-1])

        if red_qur_num > 4300000:
            redundant_count -= 1
            break
        print("PKT[%d] Found: response to [%d]"%(red_res_num, red_qur_num, ))

        red_qry_time = float(Loader.get_packet_num(red_qur_num)['_source']['layers']['frame']['frame.time_epoch'])
        
        temp_num = red_qur_num - 1
        temp_cache = {}
        ok = False
        query_ns = False
        add_on = -1
        ns_record_num = -1
        ### Find the pkt which ns record is received
        while True:
            p = Loader.get_packet_num(temp_num)
            try:
                dnslayer = p['_source']['layers']['dns']
                nsrecord = dnslayer['Additional records']
                nskeys = nsrecord.keys()
                #print("pkt[%d]:"%(temp_num,))
                
                nss = []
                for k in nskeys:
                    nss.append(nsrecord[k]['dns.resp.name'])
                    if nsrecord[k]['dns.resp.name'] == ns:
                        ### Found the ns record
                        #print(nsrecord[k]['dns.resp.name'],ns)
                        ok = True

                # if ok and "Queries" in dnslayer.keys():
                #     for key in dnslayer["Queries"].keys():
                #         if "dns.qry.name" in dnslayer["Queries"][key]:
                #             #print(dnslayer["Queries"][key]["dns.qry.name"], nss)
                #             if dnslayer["Queries"][key]["dns.qry.name"] in nss:
                #                 query_ns = True

                if ok:
                    for k in nskeys:
                        if 'dns.aaaa' in nsrecord[k].keys():
                            temp_cache[nsrecord[k]['dns.aaaa']] = nsrecord[k]['dns.resp.name']
                        if 'dns.a' in nsrecord[k].keys():
                            temp_cache[nsrecord[k]['dns.a']] = nsrecord[k]['dns.resp.name']
            except:
                pass
            
            if ok:
                ns_record_num = temp_num
                break

            temp_num -= 1
            if temp_num == 0:
                break
        
        if ok == False:
            print("PKT[%d] Fault: no ns record"%(red_res_num,))
            badf.write("PKT[%d] Fault: no ns record\n"%(red_res_num,))
            continue

        ### Find the queries without reply
        temp_num = red_qur_num - 1
        responses = []
        ok = False
        while True:
            p = Loader.get_packet_num(temp_num)
            try:
                dnslayer = p['_source']['layers']['dns']
                if dnslayer['dns.flags_tree']['dns.flags.response'] == '1':
                    # A response
                    responses.append(dnslayer['dns.response_to'])
                else:
                    # A query
                    ip = p['_source']['layers']['ip']['ip.dst']
                    if ip in temp_cache.keys():
                        if p['_source']['layers']['frame']['frame.number'] not in responses:
                            # A no-reply query
                            qry_time = float(Loader.get_packet_num(temp_num)['_source']['layers']['frame']['frame.time_epoch'])
                            times.append(red_qry_time - qry_time)
                            ok = True
                            break
            except:
                pass
            temp_num -= 1
            if temp_num == 0:
                break
            
        if ok == False:
            print("PKT[%d] Fault: get no ns query"%(red_res_num, ))
            badf.write("PKT[%d] Fault: get no ns query\n"%(red_res_num, ))
            continue

        ### Success
        print("PKT[%d] Success"%(red_res_num, ))
        succ += 1
           
badf.close()
print("SUC[%d]/ALL[%d]"%(succ,redundant_count,))

ff = open("timeouts.txt", "w+")
for t in times:
    ff.write(str(t)+"\n")
ff.close()