#!bin/python

import socket
import json
from flask import Flask, request, Response, make_response
from time import sleep

################
# DISCLAIMER: this code is for a proto - Flask is not Async, which means it can only serve one concurrent user at a time
# ideally, it should:
# - not use WerkZeug but Tornado
# - be loadbalanced behind NGNIX or similar
# - get the Socket piece of code to be async, using some flavor of GEvent or Twister like native asyng
################
# TODOS:
# - add a timeout in the socket code since it is blocking, you don't want it to hang for like 2s and not be able to serve other request
################

asnToolApp = Flask(__name__)

# GLOBALS
CYMRU_HOST = 'whois.cymru.com'
CYMRU_PORT = 43

# a whois server can be talked to by sending commands to a TCP_43 socket
# hence using a poorman's Netcat
def netcat(hostname, port, content):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, port))
    s.sendall(content)
    s.shutdown(socket.SHUT_WR)
    response = ''
    while 1:
        data = s.recv(1024)
        if not data:
			break
        response += data
        # the sleep() below was meant for Stefan to explain to me that Flask was NOT ASYNC
        # therefore Proto - one call to the endpoint stalls any other concurrent call until it is answered 
        #sleep(5)
    return response
    s.close()

@asnToolApp.route('/asn/<path:asnFlatList>/')
def queryAsn(asnFlatList):
	""" Flask wrapped function to figure out name and country details of an asNumber
	asnList:	comma separated list of values for each ASN to be queries against
	USES TEAM CYMRU's WHOIS SERVER: http://www.team-cymru.org/Services/ip-to-asn.html"""

	asnList = [int(x) for x in asnFlatList.split(',')]
	query = 'begin\r\n'
	for asn in asnList:
		query += 'as' + str(asn) + '\r\n'
	query += 'end\r\n'

	# calling the poorman's netcat python port function from above
	tmpResponse = netcat(CYMRU_HOST, CYMRU_PORT, query)
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
	return Response(json.dumps(formattedResult), content_type = 'application/json', headers = {'Access-Control-Allow-Origin':'http://127.0.0.1'})

#def main():
#	test = queryAsn([12322,5511,6128,8220,33655,33491,33662,23253,7015])
#	print json.dumps(test, sort_keys = False, indent = 4)

############
# MAIN LOOP
############
def main():
	asnToolApp.run(host='127.0.0.1', debug=True)

if __name__ == '__main__':
	main()