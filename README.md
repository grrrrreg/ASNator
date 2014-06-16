ASNator
=======

Small Python+Flask API using team-cymru.com's bgp based whois server to return AS name and AS Country Code for a given ASN
Please read the disclaimer below as it it a prototype that has a lot of design and usage caveats because of both relying on Flask and on a whois server which might not be sized for a massively called API

# REQUIREMENTS
Python module requirements are listed in a pip freeze output under requirements.txt attached to this repo

# USE
ASNator can either be used:
- as a standalone web API
- as a module giving you access to useful functions: (via '''import asntool''')
  - '''netcat(host,port,read_size)'''
  - '''getAsnDetails(asnList=list())''' : uses netcat above to query Cymru for ASN details
  - '''isValidAutNum(aut_Num)''': tells you if an (int) ASN is valid or not according to 16 adn 32 bit ASNs allocations - handy for filter() functional programming 
##  API mode usage example:
'''curl http://127.0.0.1:8080/asn/65637,5000000000,12822,5511/ | jq .
{
  "error": [
    {
      "AS_Description": "invalid aut-num",
      "AS_Country_Code": "n/a",
      "ASN_Autnum": "65637"
    },
    {
      "AS_Description": "invalid aut-num",
      "AS_Country_Code": "n/a",
      "ASN_Autnum": "5000000000"
    }
  ],
  "success": [
    {
      "AS_Description": "LYNET Kommunikation AG",
      "AS_Country_Code": "DE",
      "AS_Autnum": 12822
    },
    {
      "AS_Description": "Orange S.A.",
      "AS_Country_Code": "FR",
      "AS_Autnum": 5511
    }
  ]
}'''
 


# TO-DO
- memoize w/ decorators to avoid having to hit whois.cymru.com unnecessarily
- memoize spliting an array-of-ASNs argument into multiple single ASNs so that all individual ASNs get cached
- logging
- installer
- fix the ASN provided as string

# DISCLAIMER: 
this code is for a proto - Flask is not Async, which means it can only serve one concurrent user at a time
ideally, it should:
- not use WerkZeug but Tornado or some WGSI capable
- current config runs on localhost:8080, change that in the main loop if you want

# CREDITS:
-  uses Team Cymru's awesome WHOIS, look at http://www.team-cymru.org/Services/ip-to-asn.html for more details

# WARNING: 
please let CYMRU know if this is going to be used in prod and/or intend to massively query their whois.
In which case it is strongly advised to implement some flavor of caching
