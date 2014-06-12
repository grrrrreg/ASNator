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
# host/port couple is using a tuple, because the socket lib does too
def netcat((hostname, port), content):
	try:
	    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	    #trap: socket..socket.connect() takes a tuple in argument
	    s.connect((hostname, port))
	    s.sendall(content)
	    s.shutdown(socket.SHUT_WR)
	    response = ''
	    while True:
	        data = s.recv(4096)
	        if not data:
				break
	        response += data
	        # the sleep() below was meant to demonstrate Flask was NOT ASYNC and not meant to
	        # therefore Proto - one call to the endpoint stalls any other concurrent call until it is answered 
	        # from time import sleep
	        # sleep(5)
	    return response
	finally:
		s.close()

@asnToolApp.route('/asn/<path:asnFlatList>/')
def queryAsn(asnFlatList):
	""" Flask wrapped function to figure out name and country details of an asNumber
	asnList:	comma separated list of values for each ASN to be queries against
	USES TEAM CYMRU's WHOIS SERVER: http://www.team-cymru.org/Services/ip-to-asn.html"""

	#checks if ?format=csv is used as a query arg
	if request.args.get('format'):
		outFormat = request.args.get('format')
	else:
		outFormat = None;


	# taking ASN list from the route <path:asnFlatList> (coma separated)
	# and building the begin/end wrapped input to Cymru's whois
	asnList = [int(x) for x in asnFlatList.split(',')]
	query = 'begin\r\n'
	for asn in asnList:
		query += 'as' + str(asn) + '\r\n'
	query += 'end\r\n'

	# calling the poorman's netcat python port function from above
	tmpResponse = netcat((CYMRU_HOST, CYMRU_PORT), query)
	formattedResult = []
	#result is one string with new lines, turning this into a list
	result = tmpResponse.split('\n')

	#remove header
	result.pop(0)
	#remove trailing emptyline
	result.pop(len(result)-1)
	
	i = 0
	for line in result:
		#watch out, there might be "," before the one from the country flag...
		tmp = line.split(',')
		#identify the position of the alst comma
		if len(tmp) > 1:
			countryCode = tmp[len(tmp)-1]
			orgName = ''.join(tmp[0:len(tmp)-1]).split(' ',1)[1].replace('- ','')
			
		else:
			countryCode = tmp[1]
			orgName = tmp[0]

		formattedResult.append({'asNumber':asnList[i], 'orgName':orgName, 'countryCode':countryCode})
		i += 1
	
	if outFormat:
		csvResult = '"AS_description","AS_aut-num","AS_country"\n'
		for asObject in formattedResult:
			csvResult += ','.join(['"' + str(asObject[key]) + '"' for key in asObject]) + "\n"
		return Response(csvResult, mimetype='text/csv')

	else:
		return Response(json.dumps(formattedResult), content_type = 'application/json', headers = {'Access-Control-Allow-Origin':'http://127.0.0.1'})

############
# MAIN LOOP
############
def main():
	asnToolApp.run(host='0.0.0.0', port=8080, debug=True, threaded=True)

if __name__ == '__main__':
	main()