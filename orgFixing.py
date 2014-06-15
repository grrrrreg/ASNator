#!bin/python

import requests, socket, json

# GLOBALS
CYMRU_HOST = 'whois.cymru.com'
CYMRU_PORT = 43

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

def askCymru(asList):
	# create the CYMRU WHOIS 
	cymruInput = 'begin\r\n'
	for aut-num in asList:
		cymruInput += 'as' + str(aut-num) + '\r\n'
	cymruInput += 'end\r\n'
	
	# issuing the Netcat to Cymru's Whois server port 43
	netcatResult = netcat((CYMRU_HOST, CYMRU_PORT), cymruInput)
	
	# convert response string into response array
	cymruResponse = []
	cymruResponse = netcatResult.split('\n')
	
	# cleaning up the returned object
	cymruResponse.pop(0)
	cymruResponse.pop(len(cymruResponse)-1)

	toReturn = {}
	toReturn['list-of-as'] = []
	toReturn['list-of-as'].extend(asList)
	toReturn['country-codes'] = []

	for i in range(toReturn['list-of-as']):
		toReturn['country-codes'].append(cymruResponse[i].split(',')[-1])
	}
	return toReturn



############
# MAIN LOOP
############
def main():
	r = requests.get("https://cdnadmin-eu.netflix.com/cdnadmin/org/searchOrgs?filter=.*")
	res = r.json()
	EUList = [res[x]['fullName'] + ";" + str(res[x]['cacheCount']) + ";" + str(res[x]['peeringCount']) + ";EU;" + str(res[x]['id']) + ";" + ','.join([res[x]['servingCountries'][y]['country'] for y in range(len(res[x]['servingCountries']))]) + ";" + ','.join([str(res[x]['asn'][z]) for z in range(len(res[x]['asn']))]) for x in range(len(res)) if res[x]['cacheCount'] != 0 or res[x]['peeringCount'] != 0]
	r = requests.get("https://cdnadmin.netflix.com/cdnadmin/org/searchOrgs?filter=.*")
	res = r.json()
	USList =  [res[x]['fullName'] + ";" + str(res[x]['cacheCount']) + ";" + str(res[x]['peeringCount']) + ";US;" + str(res[x]['id']) + ";" + ','.join([res[x]['servingCountries'][y]['country'] for y in range(len(res[x]['servingCountries']))]) + ";" + ','.join([str(res[x]['asn'][z]) for z in range(len(res[x]['asn']))]) for x in range(len(res)) if res[x]['cacheCount'] != 0 or res[x]['peeringCount'] != 0]

	globalList = [line for line in EUList + USList if ";;" in line]
	matchList = {}

	for line in globalList:
		asList = line.split(';',line)[-1]
		matchlist['key'] = line
		matchList['asns'] = [].extend(asList.split(','))

	print "========> PRINTING THE LIST ASes TO QUERY ABOUT"
	print asList

	print "========> PRINTING THE LIST OF MATCHES"
	print matchList

	resultsList = askCymru(asList)
	print "========> PRINTING CYMRU RESULTS"
	print resultsList








if __name__ == '__main__':
	main()