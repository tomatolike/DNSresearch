from tools import *

PL = packet_loader()
RS = root_servers()

ifqry = 0
ifrootqry = 0
ifrootcomqry = 0
ifclient = 0
types = {}
rootqry_type_cache = {}
rootqry_name_cache = {}

for i in range(1, 4300001):
	p = PL.get_packet_num(i,"log:[%d][%d][%d][%d]"%(ifqry, ifrootqry, ifrootcomqry,ifclient))

	# Filter Out Client Queries
	try:
		if p['_source']['layers']['ip']['ip.dst'] == '172.31.40.253' and p['_source']['layers']['ip']['ip.src'] == '35.173.135.250':
			ifclient += 1
			continue
	except:
		continue

	# Find Query
	try:
		if p['_source']['layers']['dns']['dns.flags_tree']['dns.flags.response'] == '0':
			ifqry += 1
	except:
		continue

	# Find Query to Root
	try:
		ip = p['_source']['layers']['ip']['ip.dst']
		if RS.testrootserver(ip):
			ifrootqry += 1
			ty_keys = p['_source']['layers']['dns']['Queries'].keys()
			for k in ty_keys:
				ty = p['_source']['layers']['dns']['Queries'][k]['dns.qry.type']
				if ty in types.keys():
					types[ty] += 1
				else:
					types[ty] = 1
	except:
		continue

	# Find Query to Root with COM
	try:
		if RS.testrootserver(p['_source']['layers']['ip']['ip.dst']):
			for key in p['_source']['layers']['dns']['Queries'].keys():
				addr = p['_source']['layers']['dns']['Queries'][key]['dns.qry.name']
				parts = addr.split('.')
				if parts[len(parts)-1] == 'com':
					ifrootcomqry += 1
				else:
					if parts[len(parts)-1] in rootqry_name_cache.keys():
						rootqry_name_cache[parts[len(parts)-1]] += 1
					else:
						rootqry_name_cache[parts[len(parts)-1]] = 1
				qrytype = p['_source']['layers']['dns']['Queries'][key]['dns.qry.type']
				if qrytype in rootqry_type_cache.keys():
					rootqry_type_cache[qrytype] += 1
				else:
					rootqry_type_cache[qrytype] = 1
				
	except:
		continue

print(ifqry, ifrootqry, ifrootcomqry, ifclient)
print(types)
print(rootqry_name_cache)
