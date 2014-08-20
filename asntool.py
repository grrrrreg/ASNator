#!bin/python
'''Functions and API around cymru's ASN to Country and ASN Name BGP database, offers a netcat client'''

import socket, json, sys, logging
from IPy import IP, IPSet
from flask import Flask, request, Response, make_response
from types import MethodType

################
# DISCLAIMER: this code is for a proto - Flask is not Async, which means it can only serve one concurrent user at a time
# this uses threaded=True mode of Flask, but still cannot run in prod
################
# CREDITS:
# uses Team Cymru's awesome WHOIS, look at http://www.team-cymru.org/Services/ip-to-asn.html for more details
################
# WARNING: please let CYMRU know if this is going to be used in prod and/or intensively so they can scale up
# please make sure that you implement some level of caching in case you are going to massively query whois.cymru.com
################

# API CONF
API_ROOT_PATH = '/asn'
API_PORT = 8080
API_THREADED = True
API_ALLOWED_IP = '0.0.0.0'
ALLOWED_ORIGIN_HOST = '127.0.0.1'

# APP SPECIFIC CONF
CYMRU_HOST = 'whois.cymru.com'
CYMRU_PORT = 43

asn_tool_app = Flask(__name__)

def is_valid_autnum(as_number):
	'''
	Filter function, determines whether an ASN is legitimate or not.
	Acceptable aut-num should be within the ranges described here:  
	http://www.iana.org/assignments/as-numbers/as-numbers.xhtml
	Return values:
	--------------
	True if is a LEGITIMATE aut-num
	False if is an INVALID aut-num
	'''
	if isinstance(as_number, (int, long)):
		if (0 < as_number < 65536):
			return True
		else:
			if (131071 < as_number < 5000000000):
				return True
			else:
				return False
	else:
		return False

#extending IPy's IP() constructor with a few functions
# def contained_in(self, ip_range):
# 	'''
# 	extends the IP class to allow it to see whether the argument ip_range contains the instance
# 	'''
# 	if not isinstance(ip_range, IP):
# 		if isinstance(ip_range, basestring):
# 			try:
# 				netblock = IP(ip_range)
# 			except ValueError, e:
# 				raise ValueError(e)
# 		else:
# 			raise ValueError('wrong type used as IP.contained_in(arg) call - expecting string or IP')
# 	else:
# 		netblock = ip_range	
# 	if len(netblock - self) > 0:
# 		return True
# 	else:
# 		return False

# def contains(self, ip_range):
# 	'''
# 	extends the IP class to allow it to see whether the argument ip_range is contained in the instance
# 	'''
# 	if not isinstance(ip_range, IP):
# 		if isinstance(ip_range, basestring):
# 			try:
# 				netblock = IP(ip_range)
# 			except ValueError, e:
# 				raise ValueError(e)
# 		else:
# 			raise ValueError('wrong type used as IP.contained_in(arg) call - expecting string or IP')
# 	else:
# 		netblock = ip_range
# 	if len(self - netblock) > 0:
# 			return True
# 	else:
# 		return False


# THIS NEEDS TO BE CLEANED UP
# no reason why I shouldn't create a new objects that contains an IP object w/ these methods in it
#IP.contained_in = MethodType(contained_in, None, IP)
#IP.contains = MethodType(contains, None, IP)

# a whois server can be talked to by sending commands to a TCP_43 socket
# hence using a poorman's Netcat
def netcat(hostname, port, command, chunk_size=4096):
	'''
	Sends <command> to TCP port <port> of server <hostname> using a socket, listens and closes socket when no content is received anymore.
	If a response is sent, it is returned as a string.
	Arguments:
	----------
	hostname:			either fqdn or IP  
	port:				TCP
	command:			command sent to the <hostname> server
	chunk_size:			size of socket reads in bytes  
	Return value:
	-------------
	string containing the reponse from hostname to command

	Exceptions:
	-----------
	re-raises socket errors so they can be used when calling netcat()
	'''
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
		 	s.connect((hostname, port))
			try:
				s.sendall(command)
				s.shutdown(socket.SHUT_WR)
				response = ''
				while True:
				 	try:
						data = s.recv(chunk_size)
						if not data:
							break
						response += data

			  		except socket.error, e:
						logging.error('Socket_Read: cannot receive data from' + hostname + 'TCP port ' + port + ': ' + e)
						raise("NETCAT().SOCKET_READ_ERROR")
				return response
			except socket.error, e:
				logging.error('Socket_Send: cannot send command ' + command + ' to socket: ' + e)
				raise("NETCAT().SOCKET_SEND_ERROR")
		except socket.gaierror, e:
			logging.error('Socket_Address: Address-related error connecting to server: ' + e)
			raise("NETCAT().SOCKET_ADDRESS_ERROR")
		except socket.error, e:
			loggin.error('Socket_Connect: connection error, socket could not connect to' + hostname + 'TCP port ' + port + ': ' + e)
			raise("NETCAT().SOCKET_CONNECTION_ERROR")
	except socket.error, e:
		logging.error('Socket_Create: Error during socket creation phase, Exception: ' + e)
		raise("NETCAT().SOCKET_CONNECTION_ERROR")
	finally:
		s.close()

# uses the func above and wraps it into another one, simplified
# that uses only an array as argument
def get_as_details(as_list, specific_action=False):
	'''
	Uses the netcat:43 socket connection to whois.cymru.com to fetch Description and ASN for a list of aut-nums
	Arguments:
	----------
	as_list:			List of AS numbers, <int> format, i.e. without the 'as' prefix
						WARNING: only takes a LIST(array)
	specific_action:    =False if no specific action
						=validate if you want to validate that an ASN is actually a valid one (not private, not reserved
						for specific use)
	Return value:
	-------------
	response an object containing SUCCESS and ERROR arrays of response:
		{
			'success':[
				{'AS_Autnum':<aut-num>,
				'AS_Description':<ISP_Name>,
				'AS_Country_Code':<ISO_Country_Code>},
				{...},
				...
			],
			'error'  :[
				{'AS_Autnum':<invalid-aut-num>,
				'AS_Description':'invalid aut-num',
				'AS_Country_Code':null},
				{...},
				...
			]
		}

	'''
	formatted_result  = {} 
	formatted_result['success'], formatted_result['error'] =  [], []

	# test the as_list values to see if these are legit AS Numbers
	# make two lists - the idea is to return both Success and Error
	# 		- one with the valid ASNs, using filter, and the isLegitAsnFilter() filter function
	#		- the other with the negation of the afore mentioned list
	valid_asn_list = filter(is_valid_autnum, as_list)
	invalid_asn_list = [str(x) for x in as_list if x not in valid_asn_list]
		
	# in case a user defines a specific action such as "validate all ASNs passed in URL"
	if specific_action:
		if specific_action == 'validate':
			validityResult = {}
			for x in as_list:
				if x in valid_asn_list:
					validityResult[str(x)] = True
				else:
					validityResult[str(x)] = False

			return validityResult

	#if some ASNs in the list in argument are invalid, add them to the 'error' section of the response
	if len(invalid_asn_list):
		formatted_result['error'] = [{'AS_Autnum':x, 'AS_Description':'invalid aut-num', 'AS_Country_Code':'invalid aut-num'} for x in invalid_asn_list]

	# in case there is not valid ASN submitted in the query, raise an exception
	if not len(valid_asn_list):
		print "ERROR: entirely invalid ASN list:" + ', '.join([invalid_asn_list[x] for x in range(len(invalid_asn_list))])
		raise ValueError("GET_AS_DETAILS().INVALID_ASN_LIST_ERROR: " + ', '.join([invalid_asn_list[x] for x in range(len(invalid_asn_list))]))

	# create the CYMRU WHOIS bacth query
	# only using the valid ASNs to query Cymru
	cymru_input = 'begin\r\n'
	for entry in valid_asn_list:
		cymru_input += 'as' + str(entry) + '\r\n'
	cymru_input += 'end\r\n'
	
	# issuing the Netcat to Cymru's Whois server port 43
	try:
		netcat_result = netcat(CYMRU_HOST, CYMRU_PORT, cymru_input, 4096)
		
		# convert response string into response array
		cymru_response = netcat_result.split('\n')

		# cleaning up the returned object
		# removes header
		cymru_response.pop(0)
		# removes the trailing "\r\n"
		cymru_response.pop(len(cymru_response) - 1)

		i = 0
		if len(cymru_response) > 0:
			for line in cymru_response:
				#watch out, there might be "," before the one from the country flag...
				tmp = line.split(',')
				
				#identify the position of the last comma
				if len(tmp) > 1:
					country_code = tmp[-1]
					org_name = ''.join(tmp[0:len(tmp)-1]).split(' ', 1)[1].replace('- ', '')
					
				else:
					#some legit ASNs, like AS123456789 are legit but will return ['NO_NAME']
					#just skip those ones, probably unallocated ones.
					country_code = "valid but unallocated ASN"
					org_name = "valid but unallocated ASN"

				formatted_result['success'].append(
				{
					'AS_Autnum': valid_asn_list[i],
					'AS_Description': org_name,
					'AS_Country_Code': country_code
				})
				i += 1
			return formatted_result

		else:
			print("ERROR: whois to whois.cymru.com returned unexpected response length null")
			raise RuntimeError("GET_AS_DETAILS().MALFORMED_WHOIS_RESPONSE: Null Result")
	
	except socket.error, e:
		print("ERROR: SOCKET ERROR -> NETCAT ERROR -> GET_AS_DETAILS() ERROR")
		# forward the last exception
		raise

	except socket.gaierror, e:
		print("ERROR: SOCKET ERROR -> NETCAT ERROR -> GET_AS_DETAILS() ERROR")
		# forward the last exception
		raise


def get_asn_from_ip(ip_list):
	'''
	Queries Cymru's whois for a list of IPs and returns misc Routing Registry related information
	Arguments:
	----------
	ip_list:			List of IPs, string format
						WARNING: only takes a LIST(array)
	Return value:
	-------------
	response an object containing SUCCESS and ERROR arrays of response:
		{
			'success':[
				{	
					'CIDR_prefix': ,
					'CIDR_literal': <network>/<netmask>,
					'CIDR_hosts': number of hosts,
					'AS_asn': asn,
					'AS_country_code': Country code associated w/ this IP range,
					'AS_description': ISP Name
				},
				{...},
				...
			],
			'error'  :[
				{'AS_Autnum':<invalid-aut-num>,
				'AS_Description':'invalid aut-num',
				'AS_Country_Code':null},
				{...},
				...
			]
		}
	'''
	query_list, error, success = [], [], []
	if isinstance(ip_list, str):
		ip_list = [ip_list]
	
	if isinstance(ip_list, (list, tuple)):
		for ip in ip_list:
			try:
				curr_ip = IP(ip)
				if curr_ip.iptype() == 'PRIVATE':
					error.append({ip: 'rfc1918 address'})
				else:
					query_list.append(ip)
			except ValueError, e:
				logging.error('wrong get_asn_from_ip argument - IPy.IP() ValueError exception: ' + str(e))
				error.append({ip: str(e)})
				#raise ValueError(e)

	else:
		loggin.warning('get_asn_from_ip() argument is neither a string, list or tuple')
		raise ValueError('get_asn_from_ip() argument is neither a string, list or tuple')

	cymru_query = 'verbose\r\nbegin\r\n'
	for ip in query_list:
		cymru_query = cymru_query + ip + '\r\n'
	cymru_query += 'end\r\n'
	try:
		netcat_result = netcat(CYMRU_HOST, CYMRU_PORT, cymru_query, 4096)
		cymru_response = netcat_result.split('\n')[1:-1]
		for line in cymru_response:
			tmp = line.split('|')
			tmp = [' '.join(elt.split(' ')).strip() for elt in tmp]
			#print tmp
			asn = int(tmp[0])
			cidr_network = tmp[2].split('/')[0]
			cidr_length = tmp[2].split('/')[1]
			country_code = tmp[3]
			registry = tmp[4]
			tmp_as_descr = tmp[6].split(',')
			if len(tmp_as_descr) > 1:
				org_name = ''.join(tmp_as_descr[0:len(tmp_as_descr)-1]).split(' ', 1)[1].replace('- ', '')
			success.append({
				#'CIDR_net': cidr_network,
				#'CIDR_length': int(cidr_length),
				'CIDR_prefix': cidr_network + '/' + cidr_length,
				'CIDR_literal': IP(cidr_network + '/' + cidr_length).strNormal(3),
				'CIDR_hosts': len(IP(cidr_network + '/' + cidr_length)),
				'AS_asn': asn,
				'AS_country_code': country_code,
				'AS_description': org_name
			})
		response = {'success': success,'error': error}
		return response

	except socket.error, e:
		print("ERROR: SOCKET ERROR -> NETCAT ERROR -> GET_AS_DETAILS() ERROR")
		# forward the last exception
		raise

	except socket.gaierror, e:
		print("ERROR: SOCKET ERROR -> NETCAT ERROR -> GET_AS_DETAILS() ERROR")
		# forward the last exception
		raise

@asn_tool_app.route(API_ROOT_PATH + '/', defaults={'as_flat_list': ''})	
@asn_tool_app.route(API_ROOT_PATH + '/<path:as_flat_list>/')
def queryAsn(as_flat_list):
	"""Flask Route, returning [{AS_Autnum:'',AS_Country_Code:'',AS_Description:''}] for all ASes provided in /asn/<as_flat_list> or in ?query parameter
	params:
		query[<as1, as2, as3>]: coma separated list of ASNs - sets the list of ASNs to query
		format[csv]: returns a downloadable CSV file
		action[validate]: just validates wheter ASNs are valid without querying whois"""

	#checks if ?format=csv is used as a query arg
	if request.args.get('format'):
		output_format = request.args.get('format')
	else:
		output_format = None;

	#checks for an ASNList handed by queryArg instead of path, which is
	#much more RESTful - only it now might collide if I'm doing both...
	if request.args.get('query'):
		if as_flat_list:
			as_flat_list += ',' + request.args.get('query')
		else:
			as_flat_list = request.args.get('query')
	
	# taking ASN list from the route <path:asnFlatList> (coma separated)
	# and building the begin/end wrapped input to Cymru's whois
	# if a record can be transtyped into an integer, do it, else keep it string'ed
	# = preflight for the get_as_details() function
	as_list =[]
	if ',' in as_flat_list:
		for elt in as_flat_list.split(','):
			try:
				destValue = int(elt)
			except:
				destValue = str(elt)
			as_list.append(destValue)
	else:
		as_list.append(as_flat_list)

	#checks if ?action=validate is used as a query arg
	if request.args.get('action') == 'validate':
		result = get_as_details(as_list, specific_action='validate')
		return Response(json.dumps(result), content_type = 'application/json', headers = {'Access-Control-Allow-Origin':'http://' + ALLOWED_ORIGIN_HOST})

	try:
		result = get_as_details(as_list)
		
		if output_format:
			csvResult = '"is_AS_Valid","AS_Description","AS_Autnum","AS_Country"\n'
			for key in result:
				for asObject in result[key]:
					csvResult += '"' + key.upper() + '",' + ','.join(['"' + str(asObject[x]) + '"' for x in asObject]) + "\n"
			return Response(csvResult, mimetype='text/csv')

		else:
			return Response(json.dumps(result), content_type = 'application/json', headers = {'Access-Control-Allow-Origin':'http://' + ALLOWED_ORIGIN_HOST})

	except socket.error, e:
		error_response = make_response(json.dumps({'error_code':'510', 'error_descr':str(e)}), 510)
		error_response.headers['content-type'] = 'application/json'
		return error_response

	except socket.gaierror, e:
		error_response = make_response(json.dumps({'error_code':'511', 'error_descr':str(e)}), 511)
		error_response.headers['content-type'] = 'application/json'
		return error_response

	except RuntimeError, e:
		error_response = make_response(json.dumps({'error_code':'512', 'error_descr':str(e)}), 512)
		error_response.headers['content-type'] = 'application/json'
		return error_response

	except ValueError, e:
		error_response = make_response(json.dumps({'error_code':'410', 'error_descr':str(e)}), 410)
		error_response.headers['content-type'] = 'application/json'
		return error_response

@asn_tool_app.route(API_ROOT_PATH + '/help/')
def show_api_doc():
	'''Auto documentation endpoint, sits at the root path of this API'''
	api_endpoints = []
	func_count = 0
	for rule in asn_tool_app.url_map.iter_rules():
		if rule.endpoint not in [api_endpoints[x]['func'] for x in (range(len(api_endpoints)))] and rule.endpoint != 'static':
			curr_func = {}
			curr_func['func'] = rule.endpoint
			curr_func['descr'] = (asn_tool_app.view_functions[rule.endpoint].__doc__).split("\n\tparams:\n\t\t")[0]
			curr_params = (asn_tool_app.view_functions[rule.endpoint].__doc__).split("\n\tparams:\n\t\t")
			if len(curr_params) > 1:
				curr_func['optionnal_params'] =[]
				for param in curr_params[1].split("\n\t\t"):
					curr_func['optionnal_params'].append(
					{
						'name_values':'?' + param.split(': ')[0].replace('[','=[').replace("]=","="),
						'descr': param.split(': ')[1]
					})
			else:
				curr_params = ''
			curr_func['routes'] = []
			api_endpoints.append(curr_func)
			for rule_rescan in asn_tool_app.url_map.iter_rules():
				if rule_rescan.endpoint != 'static' and rule_rescan.endpoint == rule.endpoint:
					api_endpoints[func_count]['routes'].append(
					{
						'route':rule_rescan.rule,
						'allowed_methods':', '.join(list(rule_rescan.methods))
					})
			func_count += 1		
	return Response(json.dumps(api_endpoints), content_type = 'application/json', headers = {'Access-Control-Allow-Origin':'http://' + ALLOWED_ORIGIN_HOST})

############
# MAIN LOOP
############
def main():
	# first off, extend the IP class from IPy with a few methods - MONKEY PATCHIN == BAD IDEA
	

	asn_tool_app.run(host=API_ALLOWED_IP, port=API_PORT, debug=True, threaded=API_THREADED)

if __name__ == '__main__':
	main()