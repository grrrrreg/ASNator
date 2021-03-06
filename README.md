ASNator
=======

Small Python+Flask API using team-cymru.com's bgp based whois server to return AS name and AS Country Code for a given ASN
Please read the disclaimer below as it it a prototype that has a lot of design and usage caveats because of both relying on Flask and on a whois server which might not be sized for a massively called API

## Requirements
Python module requirements are listed in a pip freeze output under requirements.txt attached to this repo
To isntall the dependencies:
```
pip install -r requirements.txt
```
> at some point in a distant future I will try and package it...

## Using ASNator
ASNator can either be used:
- as a standalone web API
- as a module giving you access to useful functions: (via ```import asntool```)
	- ```netcat(host,port,read_size)```
	- ```getAsnDetails(asnList=list())``` : uses netcat above to query Cymru for ASN details
	- ```isValidAutNum(aut_Num)```: tells you if an (int) ASN is valid or not according to 16 adn 32 bit ASNs allocations - handy for filter() functional programming 

## API mode usage example:
### json output mode
By default, the output *content-type* is a valid *application/json*, the command below gives an input, showing a request that has been issued with both valid and invalid aut-nums  

#### RESTful mode using /asn/?query=<as1>,<as2> ....
```curl http://127.0.0.1:8080/asn/?query=41690,29169 | jq .```

Returns:
```json
{
  "error": [],
  "success": [
    {
      "AS_Description": "Dailymotion S.A.",
      "AS_Country_Code": "FR",
      "AS_Autnum": 41690
    },
    {
      "AS_Description": "Gandi SAS",
      "AS_Country_Code": "FR",
      "AS_Autnum": 29169
    }
  ]
}
```

#### loosely RESTful (aka, not RESTful, for realz) using /asn/<as1>,<as2>...
```curl http://127.0.0.1:8080/asn/65637,5000000000,12822,5511/ | jq .```
*(using the awesome <a href='http://stedolan.github.io/jq/'>jq</a> to prettyprint the output of curl, has no relevance with ASNTool itself, but is a crazy good tool for REST devs)*.

Returns:
```json
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
}
```
#### validate AS Numbers
The ```?action=validate``` will allow you to validate if an ASN is valid or not, and if it has been allocted or not.
```
curl http://127.0.0.1:8080/asn/65637,5000000000,12322,3215,tata/?action=validate
```
Will give you that answer:
```json
{
    "3215": true,
    "12322": true,
    "65637": false,
    "tata": false,
    "5000000000": false
}
```
> **note: ** AS like AS1234567 are valid from a RIR standpoint (RIPE, ARIN...), but are not allocated, these will be marked as valid (i.e. value for a "success" key in a reponse json, and will be validated by the ```?action=validate``` option

#### .csv format
csv format (Excel readable) is provided through the ?format=csv queryArg, as displayed in the example below.
```
curl http://127.0.0.1:8080/asn/65637,5000000000,12822,5511/?format=csv
```
Will give you the following CSV file:

|is_AS_Valid	|AS_Description	|AS_Autnum	|AS_Country            |
|---------------|---------------|---------------|----------------------|
|SUCCESS	|12822  	|DE	        |LYNET Kommunikation AG|
|SUCCESS	|5511	        |FR	        |Orange S.A.           |
|ERROR	        |65637	        |n/a	        |invalid aut-num       |
|ERROR	        |5000000000	|n/a	        |invalid aut-num       |

## Using as a module
### getting ASN to country and AS Descr mappings
All functions are available when importing asntool as a module, examples below.

```python 
>>> import asntool
>>> asList = asntool.getAsDetails([65637,5000000000,12822,5511])
>>> import json
>>> print json.dumps(asList, sort_keys=True, indent=4)
{
    "error": [
        {
            "ASN_Autnum": "65637", 
            "AS_Country_Code": "n/a", 
            "AS_Description": "invalid aut-num"
        }, 
        {
            "ASN_Autnum": "5000000000", 
            "AS_Country_Code": "n/a", 
            "AS_Description": "invalid aut-num"
        }
    ], 
    "success": [
        {
            "AS_Autnum": 12822, 
            "AS_Country_Code": "DE", 
            "AS_Description": "LYNET Kommunikation AG"
        }, 
        {
            "AS_Autnum": 5511, 
            "AS_Country_Code": "FR", 
            "AS_Description": "Orange S.A."
        }
    ]
}
```

Or if you want to check if an aut-num is valid:
```python
>>> import asntool
>>> if not asntool.isValidAutNum(65636):
...     print "AS65636 IS INVALID - side note: it is a private AS"
... 
AS65636 IS INVALID - side note: it is a private AS
```
You can also use the ```?action=check``` queryArg if you want to figure out which ASNs within a list are valid:
```
curl http://127.0.0.1:8080/asn/65637,5000000000,12322,3215,tata/?action=validate
```
Will give you that answer:
```json
{
"3215": true,
"12322": true,
"65637": false,
"tata": false,
"5000000000": false
}
```

### getting IP to ASN, Country, Descr mappings
This feature is not yet available decorated as an API endpoint, but still commited in the master because the function def in the module is usable by importing.
Here's an example of how it currently works, refer to the function docstring for details if you need. (also, please note that is uses python's IPy module to manipulate IP subnetting - motly for future use)
```python
>>> import asntool
>>> response = asntool.get_asn_from_ip('32.43.54.50')
>>> response
{
    'success': [
        {
          'CIDR_prefix':    '32.0.0.0/8', 
          'AS_asn':         2686, 
          'CIDR_hosts':     16777216, 
          'AS_description': 'AT&T Global Network Services LLC', 
          'AS_country_code':'US', 
          'CIDR_literal':   '32.0.0.0-32.255.255.255'
        }
      ], 
    'error': []
}
>>> 
```

## Error handling
### Querying for invalid ASNs
The HTTP Rest API will generate an HTTP Error and return a body detailing the error in case all queried ASNs are invalid.
```
curl http://127.0.0.1:8080/asn/131071,65539/
```
Will return an HTTP_421 error:
```json
{
"error_code": "421",
"error_descr": "GET_AS_DETAILS().INVALID_ASN_LIST_ERROR: 131071, 65539"
}
``` 
### Malformed whois.cymru.com
A runTimeError exception is also in place to detect malformed whois responses:
```python
	except RuntimeError, e:
		errorResponse =  make_response(json.dumps({'error_code':'420', 'error_descr':str(e)}), 420)
		errorResponse.headers['content-type'] = 'application/json'
		return errorResponse
```

### Socket errors
errors due to the ```netcat()``` function misbehaving are also taken into account and forwarded as ```socket.error``` and ```socket.gaierror``` with an 
indication on whether they are *CREATE*, *CONNECT*, *ADDRESS*, *SEND* and *RECEIVE* errors. The HTTP API catches them and sends an HTTP_41x error with an error message identifying the socket action causing triggering the exception.

## To Do
- memoize w/ decorators to avoid having to hit whois.cymru.com unnecessarily
- memoize spliting an array-of-ASNs argument into multiple single ASNs so that all individual ASNs get cached
- logging
- installer

## Disclaimer: 
this code is for a proto - Flask is not Async, which means it can only serve one concurrent user at a time
ideally, it should:
- not use WerkZeug but Tornado or some WGSI capable
- current config runs on localhost:8080, change that in the main loop if you want

## Credits:
-  uses Team Cymru's awesome WHOIS, look at http://www.team-cymru.org/Services/ip-to-asn.html for more details

## Warning: 
please let CYMRU know if this is going to be used in prod and/or intend to massively query their whois.
In which case it is strongly advised to implement some flavor of caching
