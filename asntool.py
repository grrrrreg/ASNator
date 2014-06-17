#!bin/python

import socket, json, sys
from flask import Flask, request, Response, make_response

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

asnToolApp = Flask(__name__)

# GLOBALS
CYMRU_HOST = 'whois.cymru.com'
CYMRU_PORT = 43

def isValidAutNum(as_number):
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

# a whois server can be talked to by sending commands to a TCP_43 socket
# hence using a poorman's Netcat
def netcat(hostname, port, command, chunk_size = 4096):
	'''
	Sends <command> to TCP port <port> of server <hostname> using a socket, listens and closes socket when no content is received anymore.
	If a response is sent, it is returned as a string.
	Arguments:
	----------
	hostname:			either fqdn or IP 
	port:				TCP
	command:			command sent to the <host server
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
			# still not sure I understand why socket.connect uses a tuple
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
			        except socket.error,e:
						print "SOCKET_READ_ERROR: cannot receive data from %s TCP port %d: %s" % (hostname,port,e)
						raise("NETCAT().SOCKET_READ_ERROR")
			    return response
		    except socket.error, e:
				print "SOCKET_SEND_ERROR: cannot send command %s to socket: %s" % (command,e)
				raise("NETCAT().SOCKET_SEND_ERROR")
		except socket.gaierror, e:
			print "SOCKET_ADDRESS_ERROR: Address-related error connecting to server: %s" % e
			raise("NETCAT().SOCKET_ADDRESS_ERROR")
		except socket.error, e:
			print "SOCKET_CONNECTION_ERROR: Connection error, socket could not connect to %s TCP Port %d %s" % (hostname, port, e)
			raise("NETCAT().SOCKET_CONNECTION_ERROR")
	except socket.error, e:
		print "SOCKET_CREATE_ERROR: Error during socket creation phase | EXCEPTION: %s" % e
		raise("NETCAT().SOCKET_CONNECTION_ERROR")
	finally:
		s.close()

# uses the func above and wraps it into another one, simplified
# that uses only an array as argument
def getAsDetails(asList, specificAction=False):
	'''
	Uses the netcat:43 socket connection to whois.cymru.com to fetch Description and ASN for a list of aut-nums
	Arguments:
	----------
	asList:				List of AS numbers, <int> format, i.e. without the 'as' prefix
						WARNING: only takes a LIST(array)
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

	Exceptions:
	-----------
	returns properly formed HTTP responses:
	- 4xx for invalid user inputs
	- 5xx for server errors, mostly socket related
	'''

	formattedResult , formattedResult['success'], formattedResult['error'] =  {}, [], []

	# test the asList values to see if these are legit AS Numbers
	# make two lists - the idea is to return both Success and Error
	# 		- one with the valid ASNs, using filter, and the isLegitAsnFilter() filter function
	#		- the other with the negation of the afore mentioned list
	validAsnList = filter(isValidAutNum, asList)
	invalidAsnList = [str(x) for x in asList if x not in validAsnList]
		
	# in case a user defines a specific action such as "validate all ASNs passed in URL"
	if specificAction:
		if specificAction == 'validate':
			validityResult = {}
			for x in asList:
				if x in validAsnList:
					validityResult[str(x)] = True
				else:
					validityResult[str(x)] = False

			return validityResult

	#if some ASNs in the list in argument are invalid, add them to the 'error' section of the response
	if len(invalidAsnList):
		formattedResult['error'] = [{'AS_Autnum':x, 'AS_Description':'invalid aut-num', 'AS_Country_Code':'invalid aut-num'} for x in invalidAsnList]

	# in case there is not valid ASN submitted in the query, raise an exception
	if not len(validAsnList):
		print "ERROR: entirely invalid ASN list:" + ', '.join([invalidAsnList[x] for x in range(len(invalidAsnList))])
		raise ValueError("GET_AS_DETAILS().INVALID_ASN_LIST_ERROR: " + ', '.join([invalidAsnList[x] for x in range(len(invalidAsnList))]))

	# create the CYMRU WHOIS bacth query
	# only using the valid ASNs to query Cymru
	cymruInput = 'begin\r\n'
	for entry in validAsnList:
		cymruInput += 'as' + str(entry) + '\r\n'
	cymruInput += 'end\r\n'
	
	# issuing the Netcat to Cymru's Whois server port 43
	try:
		netcatResult = netcat(CYMRU_HOST, CYMRU_PORT, cymruInput, 4096)
		
		# convert response string into response array
		cymruResponse = netcatResult.split('\n')

		# cleaning up the returned object
		# removes header
		cymruResponse.pop(0)
		# removes the trailing "\r\n"
		cymruResponse.pop(len(cymruResponse)-1)

		i = 0
		if len(cymruResponse) > 0:
			for line in cymruResponse:
				#watch out, there might be "," before the one from the country flag...
				tmp = line.split(',')
				
				#identify the position of the last comma
				if len(tmp) > 1:
					countryCode = tmp[-1]
					orgName = ''.join(tmp[0:len(tmp)-1]).split(' ',1)[1].replace('- ','')
					
				else:
					#this code seems completely wrong - if not len(tmp)>1 then there aren't two elements in tmp...
					#this needs to be fixed asap
					countryCode = tmp[1]
					orgName = tmp[0]

				formattedResult['success'].append({'AS_Autnum':validAsnList[i], 'AS_Description':orgName, 'AS_Country_Code':countryCode})
				i += 1
			return formattedResult

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
	
@asnToolApp.route('/asn/<path:asFlatList>/')
def queryAsn(asFlatList):
	""" 
	Flask wrapped function to figure out name and country details of an asNumber
	asFlatList:	comma separated list of values for each ASN to be queries against
	USES TEAM CYMRU's WHOIS SERVER: http://www.team-cymru.org/Services/ip-to-asn.html
	"""

	#checks if ?format=csv is used as a query arg
	if request.args.get('format'):
		outFormat = request.args.get('format')
	else:
		outFormat = None;

	# taking ASN list from the route <path:asnFlatList> (coma separated)
	# and building the begin/end wrapped input to Cymru's whois
	# if a record can be transtyped into an integer, do it, else keep it string'ed
	# = preflight for the getAsDetails() function
	asList =[]
	for elt in asFlatList.split(','):
		try:
			destValue = int(elt)
		except:
			destValue = str(elt)
		asList.append(destValue)

	#checks if ?action=validate is used as a query arg
	if request.args.get('action') == 'validate':
		result = getAsDetails(asList, specificAction='validate')
		return Response(json.dumps(result), content_type = 'application/json', headers = {'Access-Control-Allow-Origin':'http://127.0.0.1:8000'})

	try:
		result = getAsDetails(asList)
		
		if outFormat:
			csvResult = '"is_AS_Valid","AS_Description","AS_Autnum","AS_Country"\n'
			for key in result:
				for asObject in result[key]:
					csvResult += '"' + key.upper() + '",' + ','.join(['"' + str(asObject[x]) + '"' for x in asObject]) + "\n"
			return Response(csvResult, mimetype='text/csv')

		else:
			print result
			return Response(json.dumps(result), content_type = 'application/json', headers = {'Access-Control-Allow-Origin':'http://127.0.0.1:8000'})

	except socket.error, e:
		errorResponse =  make_response(json.dumps({'error_code':'510', 'error_descr':str(e)}), 510)
		errorResponse.headers['content-type'] = 'application/json'
		return errorResponse

	except socket.gaierror, e:
		errorResponse =  make_response(json.dumps({'error_code':'511', 'error_descr':str(e)}), 511)
		errorResponse.headers['content-type'] = 'application/json'
		return errorResponse

	except RuntimeError, e:
		errorResponse =  make_response(json.dumps({'error_code':'512', 'error_descr':str(e)}), 512)
		errorResponse.headers['content-type'] = 'application/json'
		return errorResponse

	except ValueError, e:
		errorResponse =  make_response(json.dumps({'error_code':'410', 'error_descr':str(e)}), 410)
		errorResponse.headers['content-type'] = 'application/json'
		return errorResponse

############
# MAIN LOOP
############
def main():
	asnToolApp.run(host='0.0.0.0', port=8080, debug=True, threaded=True)

if __name__ == '__main__':
	main()