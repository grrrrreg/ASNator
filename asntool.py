#!bin/python

import socket
import json
from flask import Flask, request, Response, make_response

################
# DISCLAIMER: this code is for a proto - Flask is not Async, which means it can only serve one concurrent user at a time
# ideally, it should:
# - not use WerkZeug but Tornado or some WGSI capable
# - be loadbalanced behind NGNIX or similar
# - get the Socket piece of code to be async, using some flavor of GEvent or Twister like native asyng
# - current config runs on localhost:8080, change that in the main loop if you want
################
# TODOS:
# - add a timeout in the socket code since it is blocking, you don't want it to hang for like 2s and not be able to serve other request
################
# CREDITS:
# uses Team Cymru's awesome WHOIS, look at http://www.team-cymru.org/Services/ip-to-asn.html for more details
# WARNING: please let CYMRU know if this is going to be used in prod and/or intensively so they can scale up
################

asnToolApp = Flask(__name__)

# GLOBALS
CYMRU_HOST = 'whois.cymru.com'
CYMRU_PORT = 43

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
			        except socket.error,e:
						print "SOCKET_READ_ERROR: cannot receive data from %s TCP port %d: %s" % (hostname,port,e)
				sys.exit(1)
			    return response
		    except socket.error,e:
				print "SOCKET_SEND_ERROR: cannot send command %s to socket: %s" % (command,e)
				sys.exit(1)
		except socket.gaierror,e:
			print "SOCKET_ADDRESS_ERROR: Address-related error connecting to server: %s" % e
			sys.exit(1)
		except socket.error,e:
			print "SOCKET_CONNECTION_ERROR: Connection error, socket could not connect to %s TCP Port %d %s" % (hostname, port, e)
			sys.exit(1)	
	except socket.error, e:
		print "SOCKET_CREATE_ERROR: Erroe during socket creation phase | EXCEPTION: %s" % e
		sys.exit(1)
	finally:
		s.close()

# uses the func above and wraps it into another one, simplified
# that uses only an array as argument
def getAsDetails(asList):
	'''
	Uses the netcat:43 socket connection to whois.cymru.com to fetch Description and ASN for a list of aut-nums
	Arguments:
	----------
	asList:				List of AS numbers, <int> format, i.e. without the 'as' prefix
						WARNING: only takes a LIST(array)
	Return value:
	-------------
	response is an array of objects as described below:
		[{'AS_Autnum':<as_number>, 'AS_Description':<ISP_Name>, 'AS_Country_Code':<ISO_Country_Code>}, {...}, ...]
	'''
	# create the CYMRU WHOIS bacth query
	cymruInput = 'begin\r\n'
	for autNum in asList:
		cymruInput += 'as' + str(autNum) + '\r\n'
	cymruInput += 'end\r\n'
	
	# issuing the Netcat to Cymru's Whois server port 43
	netcatResult = netcat(CYMRU_HOST, CYMRU_PORT, cymruInput, 4096)
	
	# convert response string into response array
	cymruResponse = []
	cymruResponse = netcatResult.split('\n')
	
	# cleaning up the returned object
	cymruResponse.pop(0)
	cymruResponse.pop(len(cymruResponse)-1)

	formattedResult = []
	i = 0
	for line in cymruResponse:
		#watch out, there might be "," before the one from the country flag...
		tmp = line.split(',')
		
		#identify the position of the last comma
		if len(tmp) > 1:
			countryCode = tmp[-1]
			orgName = ''.join(tmp[0:len(tmp)-1]).split(' ',1)[1].replace('- ','')
			
		else:
			countryCode = tmp[1]
			orgName = tmp[0]

		formattedResult.append({'AS_Autnum':asList[i], 'AS_Description':orgName, 'AS_Country_Code':countryCode})
		i += 1

	return formattedResult

@asnToolApp.route('/asn/<path:asFlatList>/')
def queryAsn(asFlatList):
	""" Flask wrapped function to figure out name and country details of an asNumber
	asFlatList:	comma separated list of values for each ASN to be queries against
	USES TEAM CYMRU's WHOIS SERVER: http://www.team-cymru.org/Services/ip-to-asn.html"""

	#checks if ?format=csv is used as a query arg
	if request.args.get('format'):
		outFormat = request.args.get('format')
	else:
		outFormat = None;

	# taking ASN list from the route <path:asnFlatList> (coma separated)
	# and building the begin/end wrapped input to Cymru's whois
	asList = [int(x) for x in asFlatList.split(',')]
	result = getAsDetails(asList)
	
	if outFormat:
		csvResult = '"AS_Description","AS_Autnum","AS_Country"\n'
		for asObject in result:
			csvResult += ','.join(['"' + str(asObject[key]) + '"' for key in asObject]) + "\n"
		return Response(csvResult, mimetype='text/csv')

	else:
		return Response(json.dumps(result), content_type = 'application/json', headers = {'Access-Control-Allow-Origin':'http://127.0.0.1'})

############
# MAIN LOOP
############
def main():
	asnToolApp.run(host='0.0.0.0', port=8080, debug=True, threaded=True)

if __name__ == '__main__':
	main()