from tools import *
import os
import socket

# Start analyzing 
## Read real-time analyze result:
f = open('res/simple.txt')
lines = f.readlines()
f.close()


## Go through all lines and find Redundant [com]
redundant_count = 0
redundant_com_count = 0
succ = 0
succ_com = 0
fail1 = 0
fail2 = 0
i = 0
Loader = packet_loader()
cache = {}
RS = root_servers()
pf = open("prove_time.txt","w+")

for i in range(0,len(lines)):
    if "Redundant[" in lines[i]:
        ### Found a redundant
        fip = getfromip(lines[i])
        if RS.testrootserver(fip) == False:
            continue
        qry_type = getqrytype(lines[i-1])
        if qry_type == 2:
            continue
        redundant_count += 1
        if "name[com]" in lines[i]:
            redundant_com_count += 1
        ### Find out which ns it is querying
        ns = [getqueryname(lines[i-1])]
        red_res_num = getpktnumber(lines[i-2])
        red_qur_num = getqrypktnum(lines[i-1])

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
            query_ns = False
            try:
                dnslayer = p['_source']['layers']['dns']
                nsrecord = dnslayer['Additional records']
                nskeys = nsrecord.keys()
                #print("pkt[%d]:"%(temp_num,))
                
                nss = []
                for k in nskeys:
                    nss.append(nsrecord[k]['dns.resp.name'])
                    if nsrecord[k]['dns.resp.name'] in ns:
                        ### Found the ns record
                        #print(nsrecord[k]['dns.resp.name'],ns)
                        ok = True

                if ok:
                    for k in nskeys:
                        if 'dns.aaaa' in nsrecord[k].keys():
                            temp_cache[nsrecord[k]['dns.aaaa']] = nsrecord[k]['dns.resp.name']
                        if 'dns.a' in nsrecord[k].keys():
                            temp_cache[nsrecord[k]['dns.a']] = nsrecord[k]['dns.resp.name']
            except:
                pass
            
            if ok:
                ns = nss
                ns_record_num = temp_num
                break

            temp_num -= 1
            if temp_num == 0:
                break
        
        if ok == False:
            print("PKT[%d] Fault: no ns record"%(red_res_num,))
            fail1 += 1
            continue

        ### FInd the real query
        real_query = ""
        while True:
            p = Loader.get_packet_num(temp_num)
            query_ns = False
            try:
                dnslayer = p['_source']['layers']['dns']

                if ok and "Queries" in dnslayer.keys():
                    for key in dnslayer["Queries"].keys():
                        if "dns.qry.name" in dnslayer["Queries"][key]:
                            real_query = dnslayer["Queries"][key]["dns.qry.name"]
                            if dnslayer["Queries"][key]["dns.qry.name"] in ns:
                                query_ns = True

                if query_ns == False:
                    break
            except:
                pass
            temp_num -= 1
            if temp_num == 0:
                break

        if query_ns == True:
            print("PKT[%d] Fault: no real query"%(red_res_num,))
            fail2 += 1
            continue

        ###
        print("SUCESS")
        succ += 1
        if "name[com]" in lines[i]:
            succ_com += 1

        if real_query not in cache.keys():
            cache[real_query] = temp_cache

        ### TEST
        os.system("sudo iptables -F")
        for ip in temp_cache.keys():
            cmd = "sudo iptables -A OUTPUT -d "+ip+" -j  DROP"
            os.system(cmd)
        
        print("Query:",real_query)
        pf.write(real_query + " " + str(time.time()) + "\n")
        try:
            res = socket.gethostbyname(real_query)
            print(res)
        except:
            pass

        time.sleep(10)
        
pf.close()

print("SUC[%d]/ALL[%d]"%(succ,redundant_count,),fail1,fail2)
print("COM:SUC[%d]/ALL[%d]"%(succ_com,redundant_com_count,))

ff = open("query_ns.txt","w+")
string = json.dumps(cache)
ff.write(string)
ff.close()