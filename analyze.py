#!/usr/bin/python
# Provided extracted data from wireshark processes the packet as a real NJE packet
# and displays the information/contents to stdout

# By Philip Young (c) 2016
# MIT License

import njelib
import sys

nje = njelib.NJE()
nje.set_debuglevel(1)
nje.set_offline()
nje.analyze(sys.argv[1])

print "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
print '[+] Analysis Complete\n'

if len(nje.getNMR()) > 0:
    print "[+] NMR Records"

for record in nje.getNMR():
    print "==================="
    if 'NMRUSER' in record:
        print "[+] User Message"
        print "[+] To User:", record['NMRUSER']
        print "[+] Message:", record['NMRMSG']

    for i in sorted(record):
        print 'record['+i+'] : %r' % record[i]

if len(nje.getSYSIN()) > 0:
    print "[+] SYSIN Records"

for record in nje.getSYSIN():
    for i in sorted(record):
        print 'record['+i+'] : %r' % record[i]
    if 'Record' in record:
        print record['Record']

if len(nje.getSYSOUT()) > 0:
    print "[+] SYSOUT Records\n"
for record in nje.getSYSOUT():
    print "==================="
    for i in sorted(record):
        print 'record['+i+'] : %r' % record[i]
    if 'Record' in record:
        print record['Record']
