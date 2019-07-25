import njelib_py3
import sys

class TSO:
	# !/usr/bin/python
	#
	# Executes the JCL provided in the first argument
	# as the user provided as the second argument
	# and displays the information/contents to stdout

	# By Philip Young (c) 2016
	# MIT License

	def JCL(self, ohost='', rhost='', host='', filename='', username = '', password = ''):

		self.ohost = ohost
		self.rhost = rhost
		self.host = host
		self.filename = filename
		self.username = username
		self.password = password

		print("[+] OHOST:", self.ohost)
		print("[+] RHOST:", self.rhost)
		print("[+] IP   :", self.host)
		print("[+] File :", self.filename)
		print("[+] User :", self.username)

		nje = njelib_py3.NJE(self.ohost, self.rhost)
		nje.set_debuglevel(1)
		t = nje.session(self.host, port=175, timeout=2, password=self.password)
		# Notice the use of the password here to connect.
		if not t:
			print("[!] Could not connect")
			sys.exit(1)

		print("[+] Connected")
		print("===================")
		print("[+] Sending file:", self.filename)
		with open(self.filename, "r") as myfile:
			data = myfile.readlines()
		print("---------10--------20--------30---------40---------50---------60---------70---------80\n")
		for l in data:
			print(l.strip("\n"))
		print("\n---------10--------20--------30---------40---------50---------60---------70---------80")
		nje.sendJCL(self.filename, self.username)
		print("===================")
		print("[+] Response Received")
		if len(nje.getNMR()) > 0:
			print("[+] NMR Records")

		print("===================")
		for record in nje.getNMR():
			if 'NMRUSER' in record:
				print("[+] User Message")
				print("[+] To User:", record['NMRUSER'])
				print("[+] Message:", record['NMRMSG'])

		print("===================")
		print("[+] Records in SYSOUT:")
		for record in nje.getSYSOUT():
			if 'Record' in record:
				print(record['Record'])
