#!/usr/bin/python


import njelib
import argparse
import sys
import signal
import re
import time



nje = njelib.NJE("WASHDC","NEWYORK")
nje.set_debuglevel(1)
t = nje.session(host='10.10.0.200',port=175, timeout=2, password="A")
nje.dumbClient()
