ASNator
=======

Small Python+Flask API using team-cymru.com's bgp based whois server to return AS name and AS Country Code for a given ASN
Please read the disclaimer below as it it a prototype that has a lot of design and usage caveats because of both relying on Flask and on a whois server which might not be sized for a massively called API

# REQUIREMENTS
Python module requirements are listed in a pip freeze output under requirements.txt attached to this repo


# DISCLAIMER: 
this code is for a proto - Flask is not Async, which means it can only serve one concurrent user at a time
ideally, it should:
- not use WerkZeug but Tornado or some WGSI capable
- be loadbalanced behind NGNIX or similar
- get the Socket piece of code to be async, using some flavor of GEvent or Twister like native asyng
- current config runs on localhost:8080, change that in the main loop if you want

# TODOS:
- add a timeout in the socket code since it is blocking, you don't want it to hang for like 2s and not be able to serve other request

# CREDITS:
-  uses Team Cymru's awesome WHOIS, look at http://www.team-cymru.org/Services/ip-to-asn.html for more details

# WARNING: 
please let CYMRU know if this is going to be used in prod and/or inten
