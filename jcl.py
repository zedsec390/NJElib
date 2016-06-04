#!/usr/bin/python
#
# Executes the JCL provided in the first argument
# as the user provided as the second argument
# and displays the information/contents to stdout

# By Philip Young (c) 2016
# MIT License

import njelib
import sys

if len(sys.argv) < 6:
	print 'Usage: ./jcl.py RHOST OHOST ip filname username [password]'
	sys.exit(-1)
	
print "[+] RHOST:", sys.argv[1]
print "[+] OHOST:", sys.argv[2]
print "[+] IP   :", sys.argv[3]
print "[+] File :", sys.argv[4]
print "[+] User :", sys.argv[5]
if len(sys.argv) > 6:
	print "[+] Pass :", sys.argv[6]
	pwd = sys.argv[6]
else:
	pwd = ''


nje = njelib.NJE(sys.argv[1],sys.argv[2])
#nje.set_debuglevel(1)
t = nje.session(host=sys.argv[3],port=175, timeout=2, password=pwd)
# Notice the use of the password here to connect.
if not t:
	print "[!] Could not connect"
	sys.exit(1)

print "[+] Connected"
print "==================="
print "[+] Sending file:", sys.argv[4]
with open (sys.argv[4], "r") as myfile:
		    data=myfile.readlines()
print "---------10--------20--------30---------40---------50---------60---------70---------80\n"
for l in data:
    print l.strip("\n")
print "\n---------10--------20--------30---------40---------50---------60---------70---------80"
nje.sendJCL(sys.argv[4], sys.argv[5])
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
