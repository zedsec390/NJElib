#!/usr/bin/env python


import njelib
import argparse
import sys
import signal
import re
import time

if len(sys.argv) < 4:
    print(sys.argv[0], "RHOST OHOST ip [password]")
    sys.exit()

print("[+] RHOST:", sys.argv[1])
print("[+] OHOST:", sys.argv[2])
print("[+] IP   :", sys.argv[3])

if len(sys.argv) > 4:
    print("[+] Pass  :", sys.argv[4])
    password = sys.argv[4]
else:
    password = ''


nje = njelib.NJE(sys.argv[1],sys.argv[2])
nje.set_debuglevel(1)
t = nje.session(host=sys.argv[3],port=3117, timeout=2,password=password)
if t:
    nje.dumbClient()
else:
    print("[!] Error, unable to connect!")
