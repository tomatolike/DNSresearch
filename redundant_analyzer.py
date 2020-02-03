import pyshark
import os
from tools import root_servers
from tools import packet_loader

RS = root_servers()
PL = packet_loader()

number = 0
fn = 0

cache = {'test':[1]}
cache2 = {'test':[1]}
times = {0:0}
prefetch_num = 0
parral_num = 0
redundant_num = 0
query_num = 0
clean_bar = 0
keep = 10000
max_prefetch = 0
max_parral = 0
com_num = 0

basedir = ""

packets = pyshark.FileCapture('res/all.pcap')

f = open(basedir + "output"+str(fn)+".txt","a+")

for packet in packets:
    number += 1
    if number > 4300001:
        break
    try:

        port = 0
        srcport = 0
        dstport = 0
        if 'UDP' in packet:
            port = int(packet.udp.port)
            srcport = int(packet.udp.srcport)
            dstport = int(packet.udp.dstport)
        if 'TCP' in packet:
            port = int(packet.tcp.port)
            srcport = int(packet.tcp.srcport)
            dstport = int(packet.tcp.dstport)

        if dstport != 53 and srcport != 53:
            continue

        if 'DNS' in packet:
            src = packet.ip.src_host
            dst = packet.ip.dst_host

            if RS.testrootserver(src) == False and RS.testrootserver(dst) == False:
                continue

            timestamp = float(packet.sniff_timestamp)

            qry_type = "NO"
            if "qry_type" in packet.dns.field_names:
                qry_type = int(packet.dns.qry_type)

            if qry_type != 1 and qry_type != 28:
                continue

            qry_name = "NO"
            if "qry_name" in packet.dns.field_names:
                qry_name = str(packet.dns.qry_name)

            response_to = "NO"
            if "response_to" in packet.dns.field_names:
                response_to = int(packet.dns.response_to)

            resp_ttl = 0
            if "resp_ttl" in packet.dns.field_names:
                resp_ttl = int(packet.dns.resp_ttl)

            resp_type = "NO"
            if "resp_type" in packet.dns.field_names:
                resp_type = int(packet.dns.resp_type)

            resp_name = "NO"
            if "resp_name" in packet.dns.field_names:
                resp_name = str(packet.dns.resp_name)

            res_a = "NO"
            if "a" in packet.dns.field_names:
                res_a = str(packet.dns.a)

            res_a6 = "NO"
            if "aaaa" in packet.dns.field_names:
                res_a6 = str(packet.dns.aaaa)

            flag = "NO"
            if "flags_truncated" in packet.dns.field_names:
                flag = int(packet.dns.flags_truncated)

            ns = "NO"
            if "ns" in packet.dns.field_names:
                ns = str(packet.dns.ns)
            
            #times[number] = timestamp
            
            # Redundant Analyze
            if response_to != 'NO':
                # this is a response
                if (resp_type == 1 or resp_type == 28 or resp_type == 2):
                    key = str(resp_type) + "_" + resp_name
                    query_time = float(PL.get_packet_num(response_to)['_source']['layers']['frame']['frame.time_epoch'])
                    if key in cache:
                        cachelen = len(cache[key])
                        ind = cachelen - 1
                        while cache[key][ind] > query_time:
                            ind -= 1
                            if ind == -1:
                                break
                        last_time = 0
                        last_qtime = 0
                        if ind == -1:
                            last_time = query_time + 1
                        else:
                            last_time = cache[key][ind]
                            last_qtime = cache2[key][cachelen-1]

                        if query_time > last_time and query_time <= last_time + resp_ttl:
                            
                            string = "from ["+src+"] to ["+dst+"]: query["+qry_name+"] query_type["+str(qry_type)+"] response_to["+str(response_to)+"] response_type["+str(resp_type)+"] flag["+str(flag)+"] ns["+ns+"] ttl["+str(resp_ttl)+"] res["+resp_name+"] res_a["+res_a+"] res_a6["+res_a6+"]\n"
                            if query_time >= last_time + resp_ttl - 5 and resp_ttl >= 9:
                                print("\nPacket: number[%d] timestamp[%f] parral[%d]/prefetch[%d]/redundant[%d]/query[%d] max_parral[%f] max_prefetch[%f]"%(number, timestamp, parral_num, prefetch_num, redundant_num, query_num, max_parral, max_prefetch, ))
                                print("Prefecthing[%d]: last[%f] ttl[%d] now[%f] t_time[%f] diff[%f] name[%s] from[%s]"%(number, last_time, resp_ttl, query_time, last_time + resp_ttl - query_time, query_time - last_qtime, resp_name, src, ))
                                f.write("\nPacket: number[%d] timestamp[%f] parral[%d]/prefetch[%d]/redundant[%d]/query[%d] max_parral[%f] max_prefetch[%f]\n"%(number, timestamp, parral_num, prefetch_num, redundant_num, query_num, max_parral, max_prefetch, ))
                                f.write(string)
                                f.write("Prefecthing[%d]: last[%f] ttl[%d] now[%f] t_time[%f] diff[%f] name[%s] from[%s]\n"%(fn, cache[key], resp_ttl, query_time, last_time + resp_ttl - query_time, query_time - last_qtime, resp_name, src, ))
                                prefetch_num += 1
                                if last_time + resp_ttl - query_time > max_prefetch:
                                    max_prefetch = last_time + resp_ttl - query_time
                            elif query_time - last_qtime < 2:
                                print("\nPacket: number[%d] timestamp[%f] parral[%d]/prefetch[%d]/redundant[%d]/query[%d] max_parral[%f] max_prefetch[%f]"%(number, timestamp, parral_num, prefetch_num, redundant_num, query_num, max_parral, max_prefetch, ))
                                print("Parral[%d]: last[%f] ttl[%d] now[%f] t_time[%f] diff[%f] name[%s] from[%s]"%(number, last_time, resp_ttl, query_time, last_time + resp_ttl - query_time, query_time - last_qtime, resp_name, src, ))
                                f.write("\nPacket: number[%d] timestamp[%f] parral[%d]/prefetch[%d]/redundant[%d]/query[%d] max_parral[%f] max_prefetch[%f]\n"%(number, timestamp, parral_num, prefetch_num, redundant_num, query_num, max_parral, max_prefetch, ))
                                f.write(string)
                                f.write("Parral[%d]: last[%f] ttl[%d] now[%f] t_time[%f] diff[%f] name[%s] from[%s]\n"%(fn, last_time, resp_ttl, query_time, last_time+ resp_ttl - query_time, query_time - last_qtime, resp_name, src, ))
                                parral_num += 1
                                if query_time - last_qtime > max_parral:
                                    max_parral = query_time - last_qtime
                            else:
                                print("\nPacket: number[%d] timestamp[%f] parral[%d]/prefetch[%d]/redundant[%d]/query[%d] max_parral[%f] max_prefetch[%f]"%(number, timestamp, parral_num, prefetch_num, redundant_num, query_num, max_parral, max_prefetch, ))
                                print("Redundant[%d]: last[%f] ttl[%d] now[%f] p_time[%f] diff[%f] name[%s] from[%s]"%(number, last_time, resp_ttl, query_time, query_time - last_time, query_time - last_qtime, resp_name, src, ))
                                f.write("\nPacket: number[%d] timestamp[%f] parral[%d]/prefetch[%d]/redundant[%d]/query[%d] max_parral[%f] max_prefetch[%f]\n"%(number, timestamp, parral_num, prefetch_num, redundant_num, query_num, max_parral, max_prefetch, ))
                                f.write(string)
                                f.write("Redundant[%d]: last[%f] ttl[%d] now[%f] p_time[%f] diff[%f] name[%s] from[%s]\n"%(fn, last_time, resp_ttl, query_time, query_time - last_time, query_time - last_qtime, resp_name, src, ))
                                if resp_name == "com":
                                    com_num += 1
                                redundant_num += 1
                            

                        cache[key].append(timestamp)
                        cache2[key].append(query_time)

                        if len(cache[key]) > 100:
                            cache[key].pop(0)
                            cache2[key].pop(0)
                    else:
                        cache[key] = [timestamp]
                        cache2[key] = [query_time]
            else:
                # this is a query
                query_num += 1

            if os.path.getsize(basedir + "output"+str(fn)+".txt") > 1024*1024*1024*20:
                fn += 1
        
    except: 
        pass
f.close()