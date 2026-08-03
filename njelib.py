#!/usr/bin/python

## Functions used to communicate with NJE
## Created by Philip Young, aka Soldier of Fortran
#
# Based Heavily on IBM book HAS2A620:
#  "Network Job Entry: Formats and Protocols"
# Available Here: http://publibz.boulder.ibm.com/epubs/pdf/has2a620.pdf
#
#  TODO: (BeS) 2024-02-15
#     heavy cleanup and refactoring
#     handle malformed JCL disconnect e.g. $HASP124 (generate using JOBX instead of JOB on JOB stmt, for example)
#     Test other edge cases
#     TLS verification
#
#########
#
#	This program is free software: you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation, either version 3 of the License, or
#	(at your option) any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#########

import atexit
import os
import signal
import socket
import inspect
import sys
import ssl
import re
import struct
import time
import traceback
import weakref
import tempfile
from select import select
import binascii
from binascii import hexlify, unhexlify
from bitstring import BitStream, BitArray
import secrets

DEBUGLEVEL = 0
NJE_PORT = 175
SPACE = b'\x40'
SYSIN = []
SYSOUT = []
NMR = []

# Optional TLS 1.2 extras for z/OS AT-TLS (used only via addTLSCiphers())
COMPAT_TLS_CIPHERS = (
	'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:'
	'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:'
	'ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:'
	'ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:'
	'AES256-GCM-SHA384:AES128-GCM-SHA256:'
	'AES256-SHA256:AES128-SHA256:'
	'DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:'
	'DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:'
	'DHE-DSS-AES256-GCM-SHA384:DHE-DSS-AES128-GCM-SHA256:'
	'DHE-DSS-AES256-SHA256:DHE-DSS-AES128-SHA256:'
	'@SECLEVEL=1'
)

# Active sessions cleaned up on interpreter exit / SIGINT / SIGTERM
_active_sessions = weakref.WeakSet()
_exit_hooks_installed = False


def _cleanup_active_sessions():
	for nje in list(_active_sessions):
		try:
			if (
				getattr(nje, 'sock', None)
				or getattr(nje, 'connected', False)
				or getattr(nje, 'signed_on', False)
			):
				nje.disconnect(clean=True)
		except Exception:
			pass


def _install_exit_hooks():
	global _exit_hooks_installed
	if _exit_hooks_installed:
		return
	_exit_hooks_installed = True
	atexit.register(_cleanup_active_sessions)

	def _on_signal(signum, frame):
		_cleanup_active_sessions()
		signal.signal(signum, signal.SIG_DFL)
		os.kill(os.getpid(), signum)

	for sig in (getattr(signal, 'SIGINT', None), getattr(signal, 'SIGTERM', None)):
		if sig is None:
			continue
		try:
			signal.signal(sig, _on_signal)
		except (ValueError, OSError):
			# Not the main thread, or signals unavailable
			pass


def _register_session(nje):
	_install_exit_hooks()
	_active_sessions.add(nje)


def _unregister_session(nje):
	_active_sessions.discard(nje)

def my_to_bytes(a):
		# print("-->my_to_bytes",type(a))
		if type(a) == int:
			return a.to_bytes(1,"big")
		elif type(a) == bytes:
			return int.to_bytes(a,"big")
		else:
			print("->>>my_to_bytes unsupported type",type(a))
		  
def my_from_bytes(a):
		# print("--->my_from_bytes",type(a))
		if type(a) == int:
			return a.from_bytes(1,"big")
		elif type(a) == bytes:
			return int.from_bytes(a,"big")
		else:
			print("--->my_from_bytes unsupported type",type(a))

class NJE:
	def __init__(self, rhost='', ohost='', host='', port=0, password='', rip='127.0.0.1', sesskey=None):
		self.debuglevel = DEBUGLEVEL
		self.host	= host
		self.port	= port
		self.sock	= None
		self.RHOST	= self.padding(rhost)
		self.OHOST	= self.padding(ohost)
		self.TYPE	= self.padding("OPEN")  # setTLS() switches to OPEN SSL
		self.RIP	= socket.inet_aton(rip)
		self.connected	= False
		self.offline	= False
		self.server_sec = ''
		self.FCS	= ''
		self.cafile = None
		self.certfile = None 
		self.keyfile = None 
		self.certpassword = None
		self.tls_verify = True
		self.tls_check_hostname = True
		self.tls_server_hostname = None
		self.tls_extra_ciphers = None  # set by addTLSCiphers() if needed
		self.tls_after_open_delay = 0.2
		#self.OIP	 = socket.inet_aton(host)
		self.R		= b'\x00'
		self.node	= 0
		self.password	= password
		#self.own_node	= chr(0x01) # Node is default 1. Can be changed to anything
		self.own_node	= b'\x01' # Node is default 1. Can be changed to anything
		self.sequence	= 0x80
		#self.sequence	= b'\x80'
		self.use_tls_after_open = False  # enabled by setTLS()
		self.sesskey = sesskey  # APPCLU SESSION SESSKEY (text, 16 hex digits, or 8 raw bytes)
		self._secure_signon_session_key = (
			self._normalize_sesskey(sesskey)
			if sesskey not in (None, '', b'')
			else None
		)
		self.nje_secure_signon = self._secure_signon_session_key is not None
		self.secure_signon_s1 = None     # Random string sent in I record
		self.secure_signon_s2 = None     # Random string for secondary validation
		self.secure_signon_verified = False  # Track if remote verified our s1
		self.signon_rejected = False
		self.signon_error = None
		self._last_connection_event = 0
		self.signed_on = False
		self.last_activity = 0.0
		# RCBs of inbound streams whose EOF has been acknowledged.  This is
		# also used to distinguish "some SYSOUT arrived" from a fully received
		# SYSOUT job.
		self._completed_inbound_streams = []
		self._inbound_sysout_jobs = {}
		self._completed_sysout_jobs = []
		# NJHGJID identifies a job at its originating node.  Do not reuse the
		# old hard-coded value (49), because more than one NJEUPLD output can be
		# in flight on different SYSOUT streams.
		self._next_nje_job_number = secrets.randbelow(32767) + 1
		# If idle longer than this (seconds), send an NJE heartbeat before next send
		self.idle_heartbeat = 60.0
		if host:
			self.signon(self.host, self.port)


	def connect(self, host, port=0, timeout=30):
		"""Connect TCP. TLS (if enabled) is negotiated later after OPEN/ACK."""
		self.ssl = False
		if not port:
			port = NJE_PORT
		self.host = host
		self.port = port
		self.timeout = timeout
		try:
			if self.use_tls_after_open:
				print("Connecting in cleartext (TLS will upgrade after OPEN SSL)")
			else:
				print("Connecting (non-TLS)")
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(timeout)
			# Help detect dead peers; does not replace NJE-level heartbeats
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
			sock.connect((host, port))
			self.sock = sock
			self.last_activity = time.time()
			return True
		except Exception as e:
			self.msg("Plain Connection Failed: {0}".format(e))
			return False

	def disconnect(self, clean=True):
		"""Close the connection. With clean=True, send NJE type-B signoff first."""
		self.msg("Disconnecting (clean={0})".format(clean))
		sock = self.sock
		do_signoff = (
			clean
			and sock
			and self.connected
			and getattr(self, 'signed_on', False)
		)

		if do_signoff:
			try:
				self._send_signoff_record()
			except Exception as e:
				self.msg("Signoff send failed: {0}".format(e))

		self.connected = False
		self.signed_on = False
		self.sequence = 0x80
		self.sock = None
		_unregister_session(self)

		if not sock:
			return

		self._close_socket(sock, after_signoff=do_signoff)

	def _close_socket(self, sock, after_signoff=False):
		"""Close socket; after signoff wait for peer instead of TLS unwrap."""
		try:
			sock.settimeout(2.0)
		except Exception:
			pass

		if after_signoff:
			self.msg("Waiting for peer close after NJE signoff")
			try:
				while True:
					chunk = sock.recv(4096)
					if not chunk:
						self.msg("Peer closed after signoff")
						break
					self.msg("Discarded {0} byte(s) after signoff".format(len(chunk)))
			except (OSError, ssl.SSLError) as e:
				self.msg("Peer close after signoff: {0}".format(e))
			try:
				sock.close()
			except OSError:
				pass
			return

		if isinstance(sock, ssl.SSLSocket):
			try:
				raw = sock.unwrap()
				self.msg("TLS unwrap OK")
				sock = raw if raw is not None else sock
			except Exception as e:
				self.msg("TLS unwrap failed (continuing close): {0}".format(e))

		try:
			sock.shutdown(socket.SHUT_RDWR)
		except OSError:
			pass
		try:
			sock.close()
		except OSError:
			pass

	def _send_signoff_record(self):
		"""Send NCCR type B signoff."""
		self.msg("Sending  >> Signoff Record type: B")
		if not self.FCS:
			self.FCS = b"\x8F\xCF"
		self.sendNJE(b"\xF0", b"\xC2", b"\x00\x00", compress=False)

	def signoff(self):
		"""Sign off and close cleanly."""
		self.disconnect(clean=True)

	def set_offline(self):
		""" Sets the system to offline mode, used for processing
			NJE packets """
		self.msg('Offline Mode Enabled')

		self.offline = True

	def msg(self, msg, *args):
		## expects strings
		"""Print a debug message, when the debug level is > 0.

		If extra arguments are present, they are substituted in the
		message using the standard string formatting operator.

		"""

		curframe = inspect.currentframe()
		calframe = inspect.getouterframes(curframe, 2)
		caller = calframe[1][3]

		if self.debuglevel > 0:
			if self.offline:
				print('NJE: [{0}]'.format(caller), end =" ")
			else:
				print('NJE({0},{1}): [{2}]'.format(self.host, self.port, caller), end =" ")

			if args:
				#print('GOT HERE')
				print(msg, args)
			else:
				print(msg)

	def set_debuglevel(self, debuglevel):
		"""Set the debug level.
		The higher it is, the more debug output you get (on sys.stdout).
		"""
		self.debuglevel = debuglevel
		if self.debuglevel > 0:
			self.msg("Enabling Debugging Records")

	def INC_SEQUENCE(self):
		prev = self.sequence
		# BCB sequence is 4 bits under 0x80; must wrap 0x8F -> 0x80 (not 0x90)
		self.sequence = ((self.sequence & 0x0F) + 1) & 0x0F | 0x80
		self.msg("Incremented sequence number from {0} to {1}".format(prev, self.sequence))

	def changeNode(self, node):
		''' Node is the number of the node you'd like to be '''
		self.msg("Changing " + self.own_node + " to " + node)
		self.own_node = node

	def AsciiToEbcdic(self, s):
		# Assume s is bytes or string, convert to bytes first
		if (type(s) != bytes):
			s=bytes(s.encode('ascii'))
		''' Converts Ascii to EBCDIC '''
		return s.decode('ascii').encode('EBCDIC-CP-BE')

	def EbcdicToAscii(self, s):
		# Assume s is bytes or string, convert to bytes first
		if (type(s) != bytes):
			if (type(s) == str):
				s=bytes(s.encode('EBCDIC-CP-BE'))
			elif (type(s) == int):
				#s=s.to_bytes(1,"big")
				s=my_to_bytes(s)
			else:
				print("Cannot convert EbcdicToAscii, Exiting")
				raise ValueError('Cannot convert EbcdicToAscii, Exiting')
				sys.exit(-1)
		''' Converts EBCDIC to UTF-8 '''
		return s.decode('EBCDIC-CP-BE').encode('ascii')

	def initiate(self):
		""" Implement NJE initialization procedure

			From has2a620.pdf
			0 1 2 3 4 5 6 7 8 9 A B C D E F
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|  TYPE	   |	 RHOST	 |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|  RIP	|  OHOST	  | OIP   |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			| R |
			+-+-+

			TYPE : Type of request in EBCDIC characters, left justified and padded with blanks.
			   Acceptable values are OPEN, ACK, and NAK.
			RHOST: Name of the host sending the control record and is the same value as the RSCS
			   LOCAL associated with this link. This field is EBCDIC characters, left justified
			   and padded with blanks.
			RIP  : Hexadecimal value of the IP address sending the control record.
			OHOST: The name of the host expected to receive the control record. Same format as RHOST.
			OIP  : Hexadecimal value of the IP address expected to receive the control record.
			R	 : If TYPE=NAK, reason code in binary, used to return additional information.
				   Valid values are:
				   - X'01' No such link can be found
				   - X'02' Link found in active state and will be reset
				   - X'03' Link found attempting an active open.
				   - X'04' (Undocumented) Invalid RHOST with valid OHOST
		"""
		self.msg("Initiating Signon to " + self.host + ":" + str(self.port))



		ip	   = socket.gethostbyname(self.host)
		self.OIP   = socket.inet_aton(ip)
		nje_packet = (self.TYPE + self.RHOST + self.RIP + self.OHOST +
				  self.OIP + self.R )

		# print(self.EbcdicToAscii(self.TYPE))
		# print(type(self.EbcdicToAscii(self.TYPE)))
		# print(self.EbcdicToAscii(self.RHOST))
		# print(type(self.EbcdicToAscii(self.RHOST)))
		# print(self.EbcdicToAscii(self.OHOST))
		# print(type(self.EbcdicToAscii(self.OHOST)))
		# sys.exit(-1)
		t=self.EbcdicToAscii(self.TYPE).decode('ascii')
		r=self.EbcdicToAscii(self.RHOST).decode('ascii')
		o=self.EbcdicToAscii(self.OHOST).decode('ascii')
		self.msg("Sending  >> TYPE: {0} RHOST: {1} OHOST: {2}".format(t,r,o))

		self.sendData(nje_packet)

		buff   = self.getData()
		self.msg("Buffer Recieved: Length({0})".format(len(buff)))
		if len(buff) < 1:
			return False

		#b for buffer
		bTYPE  = self.EbcdicToAscii(buff[0:8])
		bRHOST = self.EbcdicToAscii(buff[8:16])
		bRIP   = buff[16:20]
		bOHOST = self.EbcdicToAscii(buff[20:28])
		bOIP   = buff[28:32]
		#print(buff.hex())
		#sys.exit()
		bR	 = struct.unpack("b", buff[32:33])[0]
		#bR = buff[32]


		self.msg("Response << TYPE: {0:s} RHOST: {1:s} OHOST: {2:s} R: {3:d}".format(bTYPE.decode(), bRHOST.decode(), bRHOST.decode(), bR))


		if bR == 4:
			print("[!] Incorrect RHOST ({0}) for OHOST: ({1})\n[!] Or RHOST already connected to OHOST"
		 		.format(self.EbcdicToAscii(self.RHOST).decode('ascii').strip(),
			 	self.EbcdicToAscii(self.OHOST).decode('ascii').strip()))
			self.disconnect()
			return False
		elif bR == 1:
			print("[!] Incorrect RHOST (" + self.EbcdicToAscii(self.RHOST).strip() + ") and/or OHOST (" + self.EbcdicToAscii(self.OHOST).strip() + ")")
			self.disconnect()
			return False
		elif bR != 0:
			print("[!] Trying to Connect to Active Connection")
			self.disconnect()
			return False
		self.connected = True

		# TLS upgrade after OPEN/ACK when setTLS() was used
		if self.use_tls_after_open:
			if self.tls_after_open_delay:
				time.sleep(self.tls_after_open_delay)
			if not self.start_tls():
				self.msg("Failed to upgrade to TLS after OPEN")
				self.disconnect()
				return False

		self.send_SOHENQ()
		buff = self.processData(self.getData())

		if buff[0]['Data'] != b'\x10\x70':
			print("[!] Sent SOH ENQ but did not recieve DLE ACK0")
			self.disconnect()
			return False

		return True

	def signon(self):
		""" Implement NJE Signon Procedures by building the initial signon records: """

		if not self.connected:
			return False

		self.signon_rejected = False
		self.signon_error = None
		self.secure_signon_verified = False

		self.send_I_record()
		#self.INC_SEQUENCE() # Increment the sequence number by 1 now
		self.records = self.processData(self.getData())
		self.process_RCB()

		if not self.connected or self.signon_rejected:
			if self.signon_error:
				self.msg("Signon rejected: {0}".format(self.signon_error))
			return False

#		self.msg("Sequence is: " + self.phex(self.sequence.to_bytes(1,"big")))
		self.msg("Sequence is: " + self.phex(my_to_bytes(self.sequence)))
		self.msg("Own Node   : " + self.phex(self.own_node))
		self.msg("Dest Node  : " + self.phex(self.target_node))
		self.signed_on = True
		_register_session(self)
		return True
	def setTLS(self, certfile=None, cafile=None, keyfile=None, password=None,
			   verify=True, check_hostname=True, server_hostname=None,
			   after_open_delay=None):
		"""Enable TLS (OPEN SSL + upgrade after OPEN/ACK).

		Uses ssl.create_default_context(). cafile trusts the server cert;
		certfile/keyfile are optional client certs. Call addTLSCiphers() if the
		peer needs extra suites beyond the OpenSSL defaults.
		"""
		self.cafile = cafile
		self.certfile = certfile
		self.keyfile = keyfile
		self.certpassword = password
		self.tls_verify = verify
		self.tls_check_hostname = bool(check_hostname and verify)
		self.tls_server_hostname = server_hostname
		if after_open_delay is not None:
			self.tls_after_open_delay = after_open_delay
		self.use_tls_after_open = True
		self.TYPE = self.padding("OPEN SSL")
		return

	def addTLSCiphers(self, ciphers=None):
		"""Add extra TLS 1.2 ciphers for mainframe interoperability.

		With no argument, uses COMPAT_TLS_CIPHERS. Pass a colon-separated
		OpenSSL cipher string to use a custom list instead. Merged with
		DEFAULT at handshake time (does not replace secure defaults alone).
		"""
		self.tls_extra_ciphers = COMPAT_TLS_CIPHERS if ciphers is None else ciphers
		return self

	def start_tls(self):
		if self.ssl:
			return True
		try:
			self.msg("Upgrading to TLS...")
			if not self.sock:
				raise OSError("no socket to upgrade")
			try:
				peer = self.sock.getpeername()
				self.msg("TCP still connected to {0}".format(peer))
			except OSError as e:
				raise OSError("TCP socket not connected before TLS ({0})".format(e))

			if self.tls_verify:
				context = ssl.create_default_context(cafile=self.cafile)
				context.check_hostname = self.tls_check_hostname
			else:
				context = ssl.create_default_context()
				context.check_hostname = False
				context.verify_mode = ssl.CERT_NONE

			if self.tls_extra_ciphers:
				try:
					# Keep DEFAULT suites, prepend/append extras for AT-TLS peers
					context.set_ciphers(self.tls_extra_ciphers + ':DEFAULT')
					self.msg("Using extra TLS ciphers plus DEFAULT")
				except ssl.SSLError as e:
					self.msg("Extra ciphers rejected ({0}); keeping defaults".format(e))

			if self.certfile:
				self.msg("Loading client certificate: {0}".format(self.certfile))
				context.load_cert_chain(
					self.certfile,
					keyfile=self.keyfile,
					password=self.certpassword,
				)

			server_hostname = self.tls_server_hostname or self.host
			self.sock = context.wrap_socket(
				self.sock,
				server_hostname=server_hostname if server_hostname else None,
				do_handshake_on_connect=False,
			)

			self.msg("Starting TLS handshake (server_hostname={0!r})".format(server_hostname))
			self.sock.do_handshake()
			self.ssl = True
			try:
				self.msg("TLS upgrade successful: {0} {1}".format(
					self.sock.version(), self.sock.cipher()))
			except Exception:
				self.msg("TLS upgrade successful")
			return True
		except Exception as e:
			self.msg("TLS Upgrade Failed: {0}".format(e))
			if self.debuglevel > 0:
				traceback.print_exc()
			return False

	def session(self, host, port=175,timeout=30, password=''):
		""" Creates an NJE session by building the connection """
		if not self.connect(host,port, timeout,):
			return False

		if not self.initiate():
			self.msg("Failed to Initiate Connection")
			return False

		if password and password != '':
			self.password = password
		elif password == '' or ( not password and not self.password ):
			self.msg("No password provided.")

		if not self.signon():
			self.msg("Failed to Signon")
			return False

		return True

	def sendNMR(self, message, cmd=False, user=''):
		"""Creates Node Message Records which can contain either Commands
			or messages"""

		RCB = b"\x9A"
		SRCB = b"\x00"

		if cmd:
			self.msg("Creating NMR Command")
			NMRFLAG  = b"\x90" #NMRFLAGC Set to 'on'. From IBM "If on, the NMR contains a command"
			NMRTO	 = self.OHOST + self.target_node # This is TO node name and number
#			NMROUT	 = (int(0).to_bytes(1,"big") * 8) # was 00:00:00:00:01:00:00:01 but no idea if it needs to be
			NMROUT	 = (my_to_bytes(int(0)) * 8) # was 00:00:00:00:01:00:00:01 but no idea if it needs to be
			NMRFM	 = self.RHOST + self.own_node
			NMRLEVEL = b"\x77" # The level, we put it as essential
			NMRTYPE  = b"\x00" # 00 for unformatted commands.
		else:
			if not user:
				self.msg("Creating NMR Message")
				NMRFLAG = b"\x10" # Console Message
				NMROUT	= b"\x00\x00\x00\x00\x00\x00\x00\x00"
			else:
				self.msg("Creating NMR Message for User: {0}".format(user))
				NMRFLAG = b"\x20"
				NMROUT	= self.padding(user.upper())
			NMRLEVEL = b"\x30" #Normal messages
			NMRTYPE = b"\x00"
			NMRTO	= self.OHOST + self.target_node # Includes NMRTOQUL
			NMRFM	 = self.RHOST + self.own_node
			NMRLEVEL = b"\x00" # The level, we put it as essential
			NMRTYPE  = b"\x00" # 00 for unformatted commands.

		NMRMSG	= self.AsciiToEbcdic(message)
#		NMRML	= len(NMRMSG).to_bytes(1,"big")
		NMRML	= my_to_bytes(len(NMRMSG))
		NMR_packet =( NMRFLAG + NMRLEVEL + NMRTYPE  + NMRML + NMRTO +
				  NMROUT + NMRFM + NMRMSG	)

		self.sendNJE(RCB, SRCB, NMR_packet, True)


	def sendNJE(self, RCB, SRCB, data, compress=False):
		""" Creates (compressed) NJE record(s)
			format is: DLE STX BCB FCS RCB SRCB <Compressed Data < 253 byte>, RCB....

		 NJE records are composed of the following:
			- TTR (Total length of the record)
			- TTB (Total length of this segment)
			- DLE & STX
			- BCB (Current sequence number)
			- FCS (The stream identifier)
			- RCB (The type of record)
			- SRCB (The sub-type of the record)
			- Data (the data, compressed for some records, not compressed for others)
				- if the data is compressed and exceeds 253 bytes it is truncated and a new
				  record is created with RCB + SRCB
		"""
		self.msg("Creating NJE Record with RCB of {0} and SRCB of {1}".format(RCB, SRCB))
		nje_record = RCB + SRCB
		if compress:
			self.msg("Compressing {0} bytes".format(len(data)))
			d = self.makeSCB(data)
			nje_record += d[0]
			self.msg("Bytes Remaining: {0}".format(d[1]))
			while d[1] > 0:
				self.msg("Record length of 255 exceeded. {0} bytes remain".format(d[1]))
				data = data[:d[1]]
				d = self.makeSCB(data)
				nje_record += RCB + SRCB + d[0]
		else:
			nje_record += data

		DS  = b"\x10" + b"\x02" #DLE-STX
		#BCB  = chr(self.sequence)
#		BCB  = self.sequence.to_bytes(1,"big")
		BCB  = my_to_bytes(self.sequence)
		FCS  = self.FCS
		TTR = self.calcTTR(DS + BCB + FCS + nje_record)
		records = TTR + DS + BCB + FCS + nje_record
		self.sendData(self.makeTTB(records))
		self.INC_SEQUENCE()
		self.msg("Sent NJE Record")

	def sendNJE_multiple(self, records, compress=True):
		""" Uses a list of tuples with RCB, SRCB and Data to create multiple NJE
			records for transmission. Used by SYSIN and SYSOUT functions. Unlike
			sendNJE this compresses by default.

		 NJE records are composed of the following:
			- TTR (Total length of the record)
			- TTB (Total length of this segment)
			- DLE & STX
			- BCB (Current sequence number)
			- FCS (The stream identifier)
			- RCB (The type of record)
			- SRCB (The sub-type of the record)
			- Data (the data, compressed for some records, not compressed for others)
				- if the data is compressed and exceeds 253 bytes it is truncated and a new
				  record is created with RCB + SRCB
		"""

		nje_record = b''

		for record in records:
			self.msg("Creating NJE Record with RCB of {0} and SRCB of {1}".format(record['RCB'], record['SRCB']))
			nje_record += record['RCB'] + record['SRCB']
			data = record['Data']
			if compress:
				self.msg("Compressing {0} bytes".format(len(data)))
				d = self.makeSCB(data)
				nje_record += d[0]
				#self.msg("Bytes Remaining: %r", d[1])
				while d[1] > 0:
					self.msg("Record length of 255 exceeded. {0} bytes remain".format(d[1]))
					data = data[-d[1]:]
					d = self.makeSCB(data)
					nje_record += record['RCB'] + record['SRCB'] + d[0]
			else:
				nje_record += data

		#adding an EOR record:
		nje_record += b"\x00"

		DS  = b"\x10" + b"\x02" #DLE-STX
#		BCB  = self.sequence.to_bytes(1,"big")
		BCB  = my_to_bytes(self.sequence)
		FCS  = self.FCS
		TTR = self.calcTTR(DS + BCB + FCS + nje_record)
		records = TTR + DS + BCB + FCS + nje_record
		self.sendData(self.makeTTB(records))
		self.INC_SEQUENCE()
		self.msg("Sent {0} NJE Records".format(len(records)))

	def sendHeartbeat(self):
		"""Reply to a peer keep-alive (TTR length 6: DLE STX BCB FCS 00)."""
		self.msg("Sending Heartbeat Reply")
		if not self.FCS:
			self.FCS = b"\x8F\xCF"
		BCB = my_to_bytes(self.sequence)
		# Must be null bytes — b"00" is ASCII '0' (0x30) and poisons the link
		record = b"\x10\x02" + BCB + self.FCS + b"\x00"
		self.sendData(self.makeTTB(self.makeTTR(record)))
		self.INC_SEQUENCE()

	def check_signoff(self, buf):
		if self.EbcdicToAscii(buf[18]) == b'B':
			print("[+] Recieved Signoff Record of type 'B'. Closing Connection.")

			return False
		else:
			return True

	def send_SOHENQ(self):

		self.msg("Sending  >> SOH ENQ")
		# SOH (0x01) and ENQ (0x2D) are control chars and are the second thing we have to send
		# for a successful connection
		SOHENQ = b"\x01\x2D"
		with_TTR = self.makeTTR( SOHENQ )
		with_TTB = self.makeTTB(with_TTR)
		self.sendData(with_TTB)

	def send_I_record(self):
		'''Creates Initial Signon Record 'I' (see HAS2A620).'''
		self.FCS = b"\x8F\xCF"
		LEN = b"\x29"
		NCCRCB = b"\xF0" # Control Record
		NCCSRCB = b"\xC9" # EBCDIC letter 'I'
		NCCIEVNT = b"\x00" * 4
		NCCIREST = b"\x00\x64" # Node Resistance
		BUFSIZE = b"\x80\x00" # Buffer Size. Set to: 32768
		PASSWORD = self.padding(self.password)*2
		# x'40' = NJE secure signon (SESSKEY), not TLS
		NCCIFLG = b"\x40" if self.nje_secure_signon else b"\x00"
		NCCIFEAT = b"\x40\x17\x00\x00"
		
		if self.nje_secure_signon:
			# Generate random 8-byte string s1 for secure signon
			self.secure_signon_s1 = self._generate_random_8bytes()
			#self.secure_signon_s1 = bytes.fromhex(b'0000000000000000')
			self.msg("Secure signon: sending s1 = {0}".format(hexlify(self.secure_signon_s1)))
			p = LEN + self.RHOST + self.own_node + NCCIEVNT + NCCIREST + BUFSIZE + self.secure_signon_s1 + self.secure_signon_s1 + NCCIFLG + NCCIFEAT
		else:
			# Regular signon, record length is 0x29 (41 bytes)
			p = LEN + self.RHOST + self.own_node + NCCIEVNT + NCCIREST + BUFSIZE + PASSWORD + NCCIFLG + NCCIFEAT
		
		self.msg("Sending  >> Initial Signon Record type: I (secure={0})".format(self.nje_secure_signon))
		self.sendNJE(NCCRCB, NCCSRCB, p)

	def padding(self, word):
		''' Converts text to EBCDIC uppercase and appends spaces until the string is 8 bytes long '''
		pad=(SPACE * (8-len(word)))
		x=self.AsciiToEbcdic(word.upper())
		return(x+pad)

	def _normalize_sesskey(self, sesskey):
		"""Return the APPCLU SESSION SESSKEY as exactly eight raw bytes.

		Accepted forms:
		  * bytes/bytearray of length 8: already-encoded raw key bytes
		  * 16 hexadecimal digits: for example D7C1E2E2E6D9C4F1
		  * up to 8 text characters: uppercased, encoded as EBCDIC, zero padded
		"""
		if isinstance(sesskey, (bytes, bytearray, memoryview)):
			raw = bytes(sesskey)
			if len(raw) == 8:
				return raw
			try:
				text = raw.decode('ascii')
			except UnicodeDecodeError as exc:
				raise ValueError(
					"sesskey bytes must be exactly 8 raw bytes or ASCII hex/text"
				) from exc
		elif isinstance(sesskey, str):
			text = sesskey
		else:
			raise TypeError(
				"sesskey must be text, 16 hexadecimal digits, or 8 raw bytes"
			)

		text = text.strip()
		hex_text = text[2:] if text.lower().startswith('0x') else text
		hex_text = re.sub(r'[\s:_-]', '', hex_text)
		if len(hex_text) == 16 and re.fullmatch(r'[0-9A-Fa-f]{16}', hex_text):
			return bytes.fromhex(hex_text)

		try:
			ascii_text = text.upper().encode('ascii')
		except UnicodeEncodeError as exc:
			raise ValueError("text sesskey must contain ASCII characters") from exc
		if len(ascii_text) > 8:
			raise ValueError(
				"text sesskey is longer than 8 characters; pass 16 hex digits for raw bytes"
			)

		# JES2 initializes MDCTIKEY to binary zeros before copying the
		# extracted SESSKEY.  A short text key therefore has X'00' bytes,
		# not EBCDIC blanks, in the unused right-hand positions.
		return self.AsciiToEbcdic(ascii_text) + (b"\x00" * (8 - len(ascii_text)))

	@staticmethod
	def _racf_des_key_from_challenge(challenge):
		"""Apply RACF's DES authentication-key transformation.

		For each challenge byte RACF XORs with X'55', shifts left one bit,
		and uses bit 7 as the odd DES parity bit.
		"""
		challenge = bytes(challenge)
		if len(challenge) != 8:
			raise ValueError(
				"NJE secure-signon challenge must be exactly 8 bytes, got {0}".format(
					len(challenge)
				)
			)

		key = bytearray(8)
		for index, value in enumerate(challenge):
			key_byte = ((value ^ 0x55) << 1) & 0xFE
			# Set the low-order bit when needed so the byte has odd parity.
			if bin(key_byte).count('1') % 2 == 0:
				key_byte |= 0x01
			key[index] = key_byte
		return bytes(key)

	@staticmethod
	def _des_encrypt_block(key, plaintext):
		"""Encrypt one eight-byte block with single DES in ECB mode."""
		key = bytes(key)
		plaintext = bytes(plaintext)
		if len(key) != 8 or len(plaintext) != 8:
			raise ValueError("DES key and plaintext must each be exactly 8 bytes")

		try:
			from Crypto.Cipher import DES
		except ImportError:
			# An 8-byte TripleDES key repeats K1 for all three operations, so
			# E(K1,D(K1,E(K1,P))) reduces to ordinary single-DES E(K1,P).
			try:
				from cryptography.hazmat.primitives.ciphers import Cipher, modes
				try:
					from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
				except ImportError:
					from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
			except ImportError as exc:
				raise RuntimeError(
					"Secure NJE signon requires pycryptodome or cryptography"
				) from exc

			encryptor = Cipher(TripleDES(key), modes.ECB()).encryptor()
			return encryptor.update(plaintext) + encryptor.finalize()

		cipher = DES.new(key, DES.MODE_ECB)
		return cipher.encrypt(plaintext)

	def _racf_secure_signon_encrypt(self, challenge):
		"""Produce NCCIPENC exactly as JES2's RACROUTE TYPE=ENCRYPT does.

		The challenge is transformed into the DES key.  The APPCLU SESSKEY
		is the eight-byte plaintext block.  This is intentionally the reverse
		of DES(key=SESSKEY, plaintext=challenge).
		"""
		if self._secure_signon_session_key is None:
			raise ValueError("secure signon requested without an APPCLU SESSKEY")

		racf_des_key = self._racf_des_key_from_challenge(challenge)
		self.msg(
			"Secure signon: RACF DES key derived from challenge = {0}".format(
				hexlify(racf_des_key)
			)
		)
		return self._des_encrypt_block(
			racf_des_key, self._secure_signon_session_key
		)

	@staticmethod
	def _current_zos_connection_event():
		"""Return the high-order word of the current z/OS TOD clock.

		JES2 connection-event sequence values are derived from STCKF. The
		TOD clock counts 2**-12 microseconds since 1900-01-01. JES2 uses
		the first fullword of that value as its four-byte CES.
		"""
		nanoseconds_since_1900 = time.time_ns() + (2208988800 * 1000000000)
		tod_clock = (nanoseconds_since_1900 * 4096) // 1000
		return (tod_clock >> 32) & 0xFFFFFFFF

	def _next_connection_event(self, remote_event=b"\x00\x00\x00\x00"):
		"""Generate a JES2-compatible connection-event sequence.

		This follows JES2's NPEVENT logic: advance beyond the largest prior
		CES, but do not use a value older than roughly 60 TOD high-word ticks
		or later than the current TOD clock.
		"""
		if len(remote_event) != 4:
			raise ValueError("connection-event sequence must be exactly 4 bytes")

		remote_value = int.from_bytes(remote_event, "big")
		current_value = self._current_zos_connection_event()
		oldest_allowed = max(0, current_value - 60)
		candidate = max(remote_value, self._last_connection_event) + 1
		if candidate < oldest_allowed:
			candidate = oldest_allowed
		if candidate > current_value:
			raise ValueError(
				"cannot generate a valid CES: previous value is later than current TOD"
			)

		self._last_connection_event = candidate
		return candidate.to_bytes(4, "big")

	def _derive_des_key(self, password):
		"""Derive an 8-byte DES key from sesskey or password (z/OS uses single DES)."""
		# Reuse the canonical SESSKEY normalization.  In particular, short
		# SESSKEY values are right-padded with X'00', matching JES2.
		if self._secure_signon_session_key is not None:
			return self._secure_signon_session_key
		
		# Ordinary NJE password fields remain EBCDIC-blank padded.
		pwd_str = password if isinstance(password, str) else password.decode('ascii')
		pwd_ebcdic = self.AsciiToEbcdic(pwd_str.upper())
		pwd_8bytes = pwd_ebcdic + (SPACE * (8 - len(pwd_ebcdic)))
		return pwd_8bytes[:8]

	def _des3_encrypt(self, plaintext, key=None):
		"""Encrypt plaintext using DES ECB mode"""
		if key is None:
			key = self._derive_des_key(self.password)
		# Use only first 8 bytes for single DES (z/OS uses single DES for secure signon)
		from Crypto.Cipher import DES
		cipher = DES.new(key[:8], DES.MODE_ECB)
		return cipher.encrypt(plaintext)

	def _des3_decrypt(self, ciphertext, key=None):
		"""Decrypt ciphertext using DES ECB mode"""
		if key is None:
			key = self._derive_des_key(self.password)
		# Use only first 8 bytes for single DES (z/OS uses single DES for secure signon)
		from Crypto.Cipher import DES
		cipher = DES.new(key[:8], DES.MODE_ECB)
		return cipher.decrypt(ciphertext)

	def _generate_random_8bytes(self):
		"""Generate a random 8-byte string for secure signon"""
		return secrets.token_bytes(8)


	def hsize(self, b_array):
		return struct.unpack('>H', b_array)[0]

	def makeTTB(self, data):
		# TTB includes it's own length of 8 plus the EOB of 4 bytes.
		return (b"\x00\x00" + struct.pack('>H', len(data)+8+4) +
				b"\x00\x00\x00\x00" + data + b"\x00\x00\x00\x00")

	def makeTTR(self, data, eor=False):
		# a datablock TTR doesn't include it's own length of 4 nor an EOB
		# dbh = data block header
		if eor:
			return b"\x00\x00" + struct.pack('>H', len(data)) + data + b"\x00"
		else:
			return b"\x00\x00" + struct.pack('>H', len(data)) + data

	def calcTTR(self, data):
		return b"\x00\x00" + struct.pack('>H', len(data))

	#def makeTTR_block_header(self, data):
		# a regular TTR doesn't include it's own length of 4 but does add an EOB for TTR which is one byte long
	#	return (b"\x00\x00" + struct.pack('>H', len(data) + 1) +
	#			b"\x00\x00\x00\x00" + data + b"\x00" )

	def readTTB(self, TTB):
		''' TTB is 4 bytes long. Only the 2nd and 3rd bytes are used as the length '''
		''' returns an int of the length '''
		return self.hsize(TTB[2:4])

	def readTTR(self, TTR):
		''' TTR is the length of the record. Only the 2nd and 3rd bytes are used as the length '''
		''' returns an int of the length '''
		return self.hsize(TTR[2:4])

	def getData(self, timeout=None):
		"""Read available data without blocking until peer close.

		timeout: seconds to wait for first byte (default: self.timeout).
		"""
		if self.offline:
			self.msg('Offline Mode: Not Retrieving data')
			return b''
		if not self.sock:
			self.msg('getData: no socket')
			return b''

		data = b''
		if timeout is None:
			timeout = getattr(self, 'timeout', 30) or 30
		try:
			r, _, _ = select([self.sock], [], [], timeout)
		except (TypeError, ValueError) as e:
			self.msg("getData select failed: {0}".format(e))
			return b''
		if not r:
			self.msg("Recieved << '' (timeout waiting for data)")
			return b''

		try:
			buf = self.sock.recv(4096)
		except socket.error as e:
			self.msg("getData recv failed: {0}".format(e))
			self.connected = False
			self.signed_on = False
			return b''
		if buf == b'':
			self.msg("Recieved << '' (peer closed)")
			self.connected = False
			self.signed_on = False
			return b''
		data += buf

		# Drain only data already queued
		while True:
			try:
				r, _, _ = select([self.sock], [], [], 0)
			except (TypeError, ValueError):
				break
			if not r:
				break
			try:
				buf = self.sock.recv(4096)
			except socket.error:
				break
			if buf == b'':
				self.connected = False
				self.signed_on = False
				break
			data += buf

		self.last_activity = time.time()
		self.msg("Recieved << '{0}'".format(self.phex(data)))
		return data

	def _process_inbound(self, timeout=None):
		"""Read one batch and run process_RCB. Returns True if any data arrived."""
		data = self.getData(timeout=timeout)
		if not data:
			return False
		self.records = self.processData(data)
		self.process_RCB()
		return True

	def _drain_inbound(self, idle=0.15, max_rounds=20):
		"""Process any pending inbound NJE until the socket is quiet."""
		for _ in range(max_rounds):
			if not self.connected or not self.sock:
				break
			if not self._process_inbound(timeout=idle):
				break

	def _ensure_session(self):
		"""Drain inbound traffic and send a heartbeat if the link was idle."""
		if not self.sock or not self.connected or not self.signed_on:
			return False
		self._drain_inbound()
		if not self.connected:
			return False
		idle = time.time() - (self.last_activity or 0)
		if self.idle_heartbeat and idle >= self.idle_heartbeat:
			self.msg("Idle {0:.0f}s; sending NJE heartbeat".format(idle))
			try:
				self.sendHeartbeat()
				self._drain_inbound(idle=0.5, max_rounds=10)
			except Exception as e:
				self.msg("Heartbeat failed: {0}".format(e))
				self.connected = False
				self.signed_on = False
				return False
		return bool(self.connected and self.sock)

	def sendData(self, data):
		"""Sends raw data to the NJE server """
		if not self.sock:
			return
		self.msg("Sending  >> '{0}'".format(self.phex(data)))
		if self.offline:
			self.msg('Offline Mode: Not Sending data')
			return
		try:
			self.sock.sendall(data)
			self.last_activity = time.time()
		except OSError as e:
			self.msg("sendData failed: {0}".format(e))
			self.connected = False
			self.signed_on = False
			raise

	def processData(self, data):
		"""Process Data Streams returns an array """
		#if not self.connected:
		#	return data

		received_data = []
		d = data
		while len(d) > 0:
			i = 1
			data = d
			total_length = self.readTTB(data) - 12
			data = data[8:-4] #The TTB is 8 bytes at the begining and a footer of 4 bytes
			self.msg("Total Length (TTB - 12): {0}".format(total_length))
			while i <= total_length:
				record_length = self.readTTR(data)
				self.msg("Record Length (TTR): {0}".format(record_length))
				current_record = data[4:4 + record_length]
				self.msg("Compressed Record: {0}".format(self.phex(current_record)))
				if record_length == 6:
					#hearbeat
					packet_dict = {
					'RCB'  : b"\x00",
					'SRCB' : b"\x00",
					'Data' : b"\x00"
					}
					received_data.append(packet_dict)
				elif record_length > 2:
					DLESTX = current_record[0:2]
					self.server_seq = current_record[2:3]
					self.FCS = current_record[3:5]
					current_record = current_record[5:]
					while len(current_record) > 1:
						packet_dict = {
							'RCB' : my_to_bytes(current_record[0]),
#							'RCB' : current_record[0].to_bytes(1,"big"),
#							'SRCB' : current_record[1].to_bytes(1,"big")
							'SRCB' : my_to_bytes(current_record[1])
							}
						current_record = current_record[2:]
						if self.compressed(packet_dict['RCB']):
							data = self.readSCB(current_record)
							packet_dict['Data'] = data[0]
							current_record = current_record[data[1]:]
						else:
							packet_dict['Data'] = current_record
							current_record = current_record[record_length:]
						self.msg("Adding Record with RCB {0} and SRCB {1}".format(packet_dict['RCB'], packet_dict['SRCB']))
						self.msg("Decompressed Record: {0}".format(self.phex(packet_dict['Data'])))
						received_data.append(packet_dict)
				else:
					packet_dict = { 'Data' :current_record}
					received_data.append(packet_dict)

				data += data[4 + record_length:]
				i += record_length + 4
				i += 1
			d = d[total_length+12:]
			self.msg("Total Length: {0}".format(len(d)))
		return received_data

	def phex(self, stuff):
		#print(stuff)
		#print(type(stuff))
		#sys.exit(-3)
		if (type(stuff) != bytes):
			print("Fatal error: phex input should be bytes")
			sys.exit(-3)

		hexed = stuff.hex()
		return ' '.join(hexed[i:i+2] for i in range(0, len(hexed), 2))

	def process_RCB(self):
		# Record Control Byte				(Pg 124)
		"""Reads the RCB and processes the record:

			00	End-of-block (BSC)
			90	Request to initiate stream (SRCB=RCB of stream to be initiated)
			A0	Permission to initiate stream (SRCB=RCB of stream to be initiated)
			B0	Negative permission or receiver cancel (SRCB=RCB of stream to be denied)
			C0	Acknowledge transmission complete (SRCB=RCB of stream received)
			D0	Ready to receive stream (SRCB=RCB of stream to be received)
			E0	BCB sequence error
			F0	General control record
			98-F8	SYSIN record
			99-F9	SYSOUT record
			9A	Operator command/console message

		"""
		prev_rcb = prev_srcb = prev_data = ''

		self.msg("Processing {0} NJE Records".format(len(self.records)))
		# for record in self.records:
		#	self.msg("record[RCB]: %r", self.phex(record['RCB']))
		#	self.msg("record[SRCB]: %r", self.phex(record['SRCB']))
		#	self.msg("record[Data]: %r", self.phex(record['Data']))
		#	self.msg("Record Len: %i", len(record['Data']))

		for record in self.records:

##			self.msg("RCB: '\\x{0:02x}'".format(int.from_bytes(record['RCB'],"big")))
			self.msg("RCB: '\\x{0:02x}'".format(my_from_bytes(record['RCB'])))
##			self.msg("SRCB: '\\x{0:02x}'".format(int.from_bytes(record['SRCB'],"big")))
			self.msg("SRCB: '\\x{0:02x}'".format(my_from_bytes(record['SRCB'])))
			#self.msg("Record: %r", self.phex(record['Data']))
	
			total_len = len(record['RCB']) + len(record['SRCB']) + len(record['Data'])
	
			if total_len == 255:
				self.msg("Record Exceeds Total Size. Truncated Record.")
				self.msg("Total Length: {0}".format(total_len))
				prev_rcb = record['RCB']
				prev_srcb = record['SRCB']
				prev_data = record['Data']
				continue

			if prev_rcb == record['RCB'] and prev_srcb == record['SRCB']:
				cur_data = prev_data + record['Data'][4:] #Skip the sequence packets
				record['Data'] = cur_data
				prev_rcb = ''

			RCB = ord(record['RCB'])

			if record['RCB'] == b"\x00" and record['SRCB'] == b'\x00' and record['Data'] == b"\x00":
				self.sendHeartbeat()


			if RCB == 0x00:
				self.msg("End-of-block (BSC) (00)")
				continue
			elif RCB == 0x90:
				self.msg("Type: Request to initiate stream (90)")
				record['stream'] = record['SRCB']
				self.msg("Stream: {0}".format(record['stream']))
				#I'll allow it
				RCB = b"\xA0"
				SRCB = record['stream']
				self.sendNJE(RCB, SRCB, b"\x00\x00")
				continue
			elif RCB == 0xA0:
				self.msg("Type: Permission to initiate stream (A0)")
				record['streaming'] = True

			elif RCB == 0xB0:
				# Stream-level cancel/deny (SRCB = stream), not full session death
				self.msg("Type: Negative permission or receiver cancel (B0)")
				if not self.signed_on:
					self.signon_rejected = True
					self.signon_error = "negative response B0, SRCB=X'{0:02X}'".format(
						my_from_bytes(record['SRCB'])
					)
			elif RCB == 0xC0:
				self.msg("Type: Acknowledge transmission complete (C0)")
			elif RCB == 0xD0:
				self.msg("Type: Ready to receive stream (D0)")
			elif RCB == 0xE0:
				self.msg("Type: BCB sequence error (E0)")
			elif RCB == 0xF0:
				self.msg("Type: General control record (F0)")
				self.process_NCCR(record)
			elif RCB == 0x9A:
				self.msg("Type: Operator command/console message (9A)")
				data = self.process_nmr(record)
				if 'NMRMSG' in data:
					self.msg("{0} >> {1}: \"{2}\"".format(data['NMRFMNOD'].strip().decode('ascii'),
										data['NMRTONOD'].strip().decode('ascii'), data['NMRMSG'].decode('ascii')))
					if 'NMRMSG' in NMR:
						data['NMRMSG'] = NMR['NMRMSG'] + "\n" + data['NMRMSG']
				NMR.append(data)
			elif (RCB & 0x0F) == 0x08:
				self.msg("Type: SYSIN record (98-F8)")
				if record['SRCB'] == b"\x00":
					self._acknowledge_stream_eof(record['RCB'])
					continue
				data = self.process_SYSIN(record)
				SYSIN.append(data)
			elif (RCB & 0x0F) == 0x09:
				self.msg("Type: SYSOUT record (99-F9)")
				if record['SRCB'] == b"\x00":
					self._acknowledge_stream_eof(record['RCB'])
					continue
				data = self.process_SYSOUT(record)
				SYSOUT.append(data)
				if data and 'NJHGJID' in data:
					self._inbound_sysout_jobs[record['RCB']] = data

	def _acknowledge_stream_eof(self, stream_rcb):
		"""Acknowledge a received SYSIN/SYSOUT EOF and close that stream."""
		self.msg(
			"End of stream X'{0:02X}'; sending transmission complete".format(
				my_from_bytes(stream_rcb)
			)
		)
		# For a stream-control record, SRCB identifies the completed stream.
		self.sendNJE(b"\xC0", stream_rcb, b"\x00\x00")
		self._completed_inbound_streams.append(stream_rcb)
		if (my_from_bytes(stream_rcb) & 0x0F) == 0x09:
			self._completed_sysout_jobs.append(
				self._inbound_sysout_jobs.pop(stream_rcb, None)
			)

	def _completed_sysout_count(self):
		"""Return the number of inbound SYSOUT streams acknowledged so far."""
		return sum(
			1 for stream in self._completed_inbound_streams
			if (my_from_bytes(stream) & 0x0F) == 0x09
		)

	def _sysout_job_completed_since(self, job_number, job_name, start_index):
		"""Return true when the selected NJE job has reached SYSOUT EOF."""
		expected_name = str(job_name).strip().upper()
		for job in self._completed_sysout_jobs[start_index:]:
			if not job or job.get('NJHGJID') != job_number:
				continue
			actual_name = job.get('NJHGJNAM', b'')
			if isinstance(actual_name, bytes):
				actual_name = actual_name.decode('ascii', errors='replace')
			if actual_name.strip().upper() == expected_name:
				return True
		return False

	def process_NCCR(self, record):
		""" Networking Connection Control Records (NCCR)
			I - Initial signon
			J - Response signon
			K - Reset signon
			L - Concurrence signon
			M - Add connection
			N - Subtract connection
			B - Signoff
			"""

		SRCB = self.EbcdicToAscii(record['SRCB']).decode('ascii')

		if SRCB == "I":
			self.msg("[NCCR] I - Initial Signon")
		elif SRCB == "J":
			self.msg("[NCCR] J - Response signon")
			record['NCCIDL'] = record['Data'][0:1]
			record['NCCINODE'] = self.EbcdicToAscii(record['Data'][1:9])
			record['NCCIQUAL'] = record['Data'][9:10]
			self.msg("NCCIQUAL: '{0}'".format(self.phex(record['NCCIQUAL'])))
			record['NCCIEVNT'] = record['Data'][10:14]
			record['NCCIREST'] = record['Data'][14:16]
			record['NCCIBUFSZ'] = record['Data'][16:18]
			
			# Handle secure vs regular signon fields
			if self.nje_secure_signon:
				self.msg("Processing secure signon response (J record)")
				# In secure signon mode:
				# Data[18:26]: NCCIPRAW (s2 from remote)
				# Data[26:34]: NCCIPENC (encrypted s1 from remote)
				record['NCCIPRAW'] = record['Data'][18:26]
				record['NCCIPENC'] = record['Data'][26:34]
				self.msg("Secure signon: received s2 = {0}".format(hexlify(record['NCCIPRAW'])))
				self.msg("Secure signon: received e_s1 = {0}".format(hexlify(record['NCCIPENC'])))
				
				# Verify remote encrypted our s1 correctly
				try:
					my_encrypted_s1 = self._racf_secure_signon_encrypt(self.secure_signon_s1)
					if my_encrypted_s1 == record['NCCIPENC']:
						self.msg("Secure signon: s1 verification SUCCESS")
						self.secure_signon_verified = True
					else:
						self.msg("Secure signon: s1 verification FAILED - remote response doesn't match")
						self.msg("Expected: {0}".format(hexlify(my_encrypted_s1)))
						self.msg("Got: {0}".format(hexlify(record['NCCIPENC'])))
						self.signon_rejected = True
						self.signon_error = "remote failed secure-signon s1 verification"
				except Exception as e:
					self.msg("Secure signon: s1 verification ERROR - {0}".format(e))
					self.signon_rejected = True
					self.signon_error = "secure-signon s1 verification error: {0}".format(e)
				
				# Store s2 for later verification in K/L record
				self.secure_signon_s2 = record['NCCIPRAW']
				record['NCCIFLG'] = record['Data'][34]
			else:
				# Regular signon mode - use password fields
				record['NCCILPAS'] = self.EbcdicToAscii(record['Data'][18:26])
				record['NCCINPAS'] = self.EbcdicToAscii(record['Data'][26:34])
				record['NCCIFLG'] = record['Data'][34]
			
			# NCCIDL includes RCB and SRCB.  The four feature bytes occupy
			# Data[35:39]; bytes beyond the declared length are SCB framing.
			record['NCCIFEAT'] = record['Data'][35:39] if record['Data'][0] >= 0x29 else b''
			self.target_node = record['NCCIQUAL']
			record['Data'] = ''
			if self.signon_rejected:
				return

			if record['NCCIEVNT'] == b"\x00\x00\x00\x00":
				# Reset the connection with type K
				self.send_reset(record['NCCIEVNT']) #Type 'K'
				self.records = self.processData(self.getData())
				self.process_RCB()
			else:
				# We're not the big boss, send concurrence
				self.send_concurrence(record['NCCIEVNT']) #Type 'L'
			return

		elif SRCB == "K":
			self.msg("[NCCR] K - Reset signon")
			if self.nje_secure_signon and len(record['Data']) >= 15 and record['Data'][0] >= 0x11:
				# K/L secure layout in Data is DL(1), EVNT(4), REST(2), PENC(8).
				# Do not use [-8:] because processData may retain SCB terminators.
				received_e_s2 = record['Data'][7:15]
				try:
					my_encrypted_s2 = self._racf_secure_signon_encrypt(self.secure_signon_s2) if self.secure_signon_s2 else None
					if my_encrypted_s2 and my_encrypted_s2 == received_e_s2:
						self.msg("Secure signon: s2 verification SUCCESS")
					else:
						self.msg("Secure signon: s2 verification FAILED")
						if my_encrypted_s2:
							self.msg("Expected: {0}".format(hexlify(my_encrypted_s2)))
							self.msg("Got: {0}".format(hexlify(received_e_s2)))
				except Exception as e:
					self.msg("Secure signon: s2 verification ERROR - {0}".format(e))
		elif SRCB == "L":
			self.msg("[NCCR] L - Concurrence signon")
			if self.nje_secure_signon and len(record['Data']) >= 15 and record['Data'][0] >= 0x11:
				# Same secure layout as K.
				received_e_s2 = record['Data'][7:15]
				try:
					my_encrypted_s2 = self._racf_secure_signon_encrypt(self.secure_signon_s2) if self.secure_signon_s2 else None
					if my_encrypted_s2 and my_encrypted_s2 == received_e_s2:
						self.msg("Secure signon: s2 verification SUCCESS")
					else:
						self.msg("Secure signon: s2 verification FAILED")
						if my_encrypted_s2:
							self.msg("Expected: {0}".format(hexlify(my_encrypted_s2)))
							self.msg("Got: {0}".format(hexlify(received_e_s2)))
				except Exception as e:
					self.msg("Secure signon: s2 verification ERROR - {0}".format(e))
		elif SRCB == "M":
			self.msg("[NCCR] M - Add connection")
		elif SRCB == "N":
			self.msg("[NCCR] N - Subtract connection")
		elif SRCB == "B":
			self.msg("[NCCR] B - Signoff")
			self.msg("Recieved Signoff Record of type 'B'. Closing Connection")
			self.signed_on = False
			self.disconnect(clean=False)

	def send_reset(self, previous_event=b"\x00\x00\x00\x00"):
		''' Builds Reset Signon Record '''
		RCB = b"\xF0"	 #NCCRCB type 0xF0
		SRCB = b"\xD2"	  #SRCB = 'K'
		NCCIEVNT = self._next_connection_event(previous_event)
		NCCIREST = b"\x00\xC8"

		if self.nje_secure_signon and self.secure_signon_s2:
			# Secure K is exactly 17 bytes including RCB/SRCB:
			#   F0 D2 11 EVNT(4) REST(2) PENC(8)
			try:
				encrypted_s2 = self._racf_secure_signon_encrypt(self.secure_signon_s2)
				self.msg("Secure signon: sending e_s2 = {0}".format(hexlify(encrypted_s2)))
				reset = b"\x11" + NCCIEVNT + NCCIREST + encrypted_s2
			except Exception as e:
				self.msg("Secure signon: failed to encrypt s2 - {0}".format(e))
				self.signon_rejected = True
				self.signon_error = "failed to encrypt secure-signon s2: {0}".format(e)
				return False
		else:
			# Non-secure K is exactly 9 bytes including RCB/SRCB.
			reset = b"\x09" + NCCIEVNT + NCCIREST

		if len(reset) + 2 != reset[0]:
			raise AssertionError("invalid K-record length")
		self.msg("Reset CES = {0}".format(hexlify(NCCIEVNT)))
		self.msg("Sending  >> Reset Signon Record type: K")
		self.sendNJE(RCB, SRCB, reset)
		return True

	def send_concurrence(self, NCCIEVNT):
		''' Builds concurrence Signon Record '''
		RCB = b"\xF0"	 #NCCRCB type 0xF0
		SRCB = b"\xD3"	  #SRCB = 'L'
		NCCIREST = b"\x00\xC8"

		if self.nje_secure_signon and self.secure_signon_s2:
			# Secure L has the same 17-byte layout as secure K.
			try:
				encrypted_s2 = self._racf_secure_signon_encrypt(self.secure_signon_s2)
				self.msg("Secure signon: sending e_s2 = {0}".format(hexlify(encrypted_s2)))
				con = b"\x11" + NCCIEVNT + NCCIREST + encrypted_s2
			except Exception as e:
				self.msg("Secure signon: failed to encrypt s2 - {0}".format(e))
				self.signon_rejected = True
				self.signon_error = "failed to encrypt secure-signon s2: {0}".format(e)
				return False
		else:
			con = b"\x09" + NCCIEVNT + NCCIREST

		if len(con) + 2 != con[0]:
			raise AssertionError("invalid L-record length")
		self.msg("Sending  >> Accept (concurrence) network SIGNON Record type: L")
		self.sendNJE(RCB, SRCB, con)
		return True

	def request_stream(self):
		""" Requests to initiate an NJE stream """
		RCB = b"\x90"
		SRCB = b"\x98"
		DATA = b"\x00\x00"
		self.msg("Requesting NJE Stream")
		self.sendNJE(RCB, SRCB, DATA)

	def process_SYSIN(self, data):
		"""
		Processes SYSIN data which is in the format as below.
		Returns a dictionary of values.

		98-F8	NJE SYSIN control information as follows:
					1000 0000 - Standard record
					1100 0000 - Job header
					1110 0000 - Data set header
					1101 0000 - Job trailer
					1111 0000 - Reserved
					1111 0000 - Reserved for IBM's use
		"""
		SRCB = ord(data['SRCB']) & 0xF0
		self.msg("Processing SYSIN. SRCB: {0}".format(data['SRCB']))
		# http://www-01.ibm.com/support/knowledgecenter/SSB27U_5.4.0/com.ibm.zvm.v54.dmta7/jhf.htm%23jhf
		d = data['Data']
		#self.msg(self.phex(d))
		job = {}

		if SRCB == 0x80:
			self.msg("Standard record")
			LRECL = ord(d[0:1])
			self.msg("Record length: {0}".format(LRECL))
			record = self.EbcdicToAscii(d[1:]).ljust(LRECL)
			self.msg("Record: {0}".format(record))
			job['Record'] = record
		elif SRCB == 0xC0:
			job.update(self.job_headers(d))
		elif SRCB == 0xE0:
			self.msg("Data set header")
		elif SRCB == 0xD0:
			job.update(self.job_footers(d))
			self.msg("Footer Length: {0}".format(job['NJTGLEN']))

		return job

	def process_SYSOUT(self, data):
		"""
		99-F9	NJE SYSOUT control information as follows:
					10cc 0000 - Carriage control type as follows:
						1000 0000 - No carriage control
						1001 0000 - Machine carriage control
						1010 0000 - ASA carriage control
						1011 0000 - CPDS page mode records (with carriage control)
					10cc ss00 - Spanned record control as follows:
						10.. 0000 - Standard record (not spanned)
						10.. 1000 - First segment of spanned record
						10.. 0100 - Middle segment of spanned record
						10.. 1100 - Last segment of spanned record
					11cc 0000 - Control record as follows:
						1100 0000 - Job header
						1110 0000 - Data set header
						1101 0000 - Job trailer
						1111 0000 - Reserved for IBM's use
		"""
		job = {}
		d = data['Data']
		self.msg("Processing SYSOUT. SRCB: {0}".format(data['SRCB']))
		if (ord(data['SRCB']) & 0xC0) == 0xC0:
			self.msg("Processing Header")
			SRCB = ord(data['SRCB']) & 0xF0
			if SRCB == 0x80:
				self.msg("Standard record")
				LRECL = ord(d[0:1])
				self.msg("Record length: {0}".format(LRECL))
				record = self.EbcdicToAscii(d[1:]).ljust(LRECL)
				self.msg("Record: {0}".format(record))
				job['Record'] = record
			elif SRCB == 0xC0:
				job.update(self.job_headers(d))
			elif SRCB == 0xE0:
				self.msg("Data set header")
				job.update(self.dataset_headers(d))
			elif SRCB == 0xD0:
				job.update(self.job_footers(d))
				self.msg("Footer Length: {0}".format(job['NJTGLEN']))
		elif (ord(data['SRCB']) & 0x8F) == 0x80:
			SRCB = ord(data['SRCB']) & 0xF0
			if SRCB == 0x80:
				self.msg("No carriage control")
				LRECL = ord(d[0:1])
				record = self.EbcdicToAscii(d[1:]).ljust(LRECL)
				self.msg("Record: {0}".format(record))
				job['Record'] = record
			elif SRCB == 0x90:
				self.msg("Machine carriage control")
			elif SRCB == 0xA0:
				self.msg("ASA carriage control")
				length = ord(d[0:1])
				self.msg("Length: {0}".format(length))
				record = self.EbcdicToAscii(d[1:])
				job['ASA'] = record[0]
				self.msg("Record: {0}".format(len(record)))
				job['Record'] = record
			elif SRCB == 0xB0:
				self.msg("CPDS page mode records (with carriage control)")

		return job

	def dataset_headers(self, d):
		self.msg("Dataset header")

		job = {
			'NDHLEN' : struct.unpack(">H",d[0:2])[0],
			'NDHFLAGS': d[2:3],
			'NDHSEQ': d[3:4]
			}

		self.msg("Length {0} vs actual {1}".format(job['NDHLEN'], len(d)))
		d = d[4:]
		header = d[2:3]
		length = struct.unpack(">H",d[0:2])[0]
		job.update( {
		'NDHGLEN'  : length,
		'NDHGTYPE' : header,
		'NDHGMOD'  : ord(d[3:4]),
		'NDHGNODE' : self.EbcdicToAscii(d[4:12]),
		'NDHGRMT'  : self.EbcdicToAscii(d[12:20]),
		'NDHGPROC' : self.EbcdicToAscii(d[20:28]),
		'NDHGSTEP' : self.EbcdicToAscii(d[28:36]),
		'NDHGDD'   : self.EbcdicToAscii(d[36:44]),
		'NDHGDSNO' : struct.unpack(">H",d[44:46])[0],
		'NDHGCLAS' : self.EbcdicToAscii(d[47]),
		'NDHGNREC' : struct.unpack(">i",d[48:52])[0],
		'NDHGFLG1' : ord(d[52:53]),
		'NDHGF1SP' : self.get_bit(ord(d[52:53]),7),
		'NDHGF1HD' : self.get_bit(ord(d[52:53]),6),
		'NDHGF1LG' : self.get_bit(ord(d[52:53]),5),
		'NDHGF1OV' : self.get_bit(ord(d[52:53]),4),
		'NDHGF1IN' : self.get_bit(ord(d[52:53]),3),
		'NDHGF1LC' : self.get_bit(ord(d[52:53]),2),
		'NDHGF1ST' : self.get_bit(ord(d[52:53]),1),
		'NDHGF1DF' : self.get_bit(ord(d[52:53]),0),
		'NDHGRCFM' : ord(d[53:54]),
		'NDHGLREC' : struct.unpack(">H",d[54:56])[0],
		'NDHGDSCT' : ord(d[56:57]),
		'NDHGFCBI' : ord(d[57:58]),
		'NDHGLNCT' : ord(d[58:59]),
		'NDHGFORM' : self.EbcdicToAscii(d[60:68]),
		'NDHGFCB'  : self.EbcdicToAscii(d[68:76]),
		'NDHGUCS'  : self.EbcdicToAscii(d[76:84]),
		'NDHGXWTR' : self.EbcdicToAscii(d[84:92]),
		'NDHGNAME' : self.EbcdicToAscii(d[92:100]),
		'NDHGFLG2' : ord(d[100:101]),
		'NDHGF2PR' : self.get_bit(ord(d[100:101]),7),
		'NDHGF2PU' : self.get_bit(ord(d[100:101]),6),
		'NDHGF2NM' : self.get_bit(ord(d[100:101]),5),
		'NDHGF2HB' : self.get_bit(ord(d[100:101]),4),
		'NDHGF2HA' : self.get_bit(ord(d[100:101]),3),
		'NDHGUCSO' : ord(d[101:102]),
		'NDHGUCSD' : self.get_bit(ord(d[101:102]),7),
		'NDHGUCSF' : self.get_bit(ord(d[101:102]),6),
		'NDHGPMDE' : self.EbcdicToAscii(d[104:112]),
		'NDHGSEGN' : struct.unpack(">i",d[112:116])[0]
		} )
		d = d[length:]



		while len(d) > 1:

			header = d[2:3]
			if header == b"\x8C":
				self.msg("Security Section of the Data Set Header")
				job.update( {
					'NDHTLEN'  : struct.unpack(">H",d[0:2])[0],
					'NDHTTYPE' : header,
					'NDHTMOD'  : d[3:4],
					'NDHTLENP' : struct.unpack(">h",d[4:6])[0], # Job identifier
					'NDHTFLG0' : ord(d[6:7]),
					'NDHTF0JB' : self.get_bit(ord(d[7:8]),7)
					} )
				d = d[8:]
				job.update( {
					'NDHTLENT' : ord(d[0:1]),
					'NDHTVERS' : ord(d[1:2]),
					'NDHTFLG1' : ord(d[2:3]),
					'NDHT1EN'  : self.get_bit(ord(d[2:3]),7),
					'NDHT1EXT' : self.get_bit(ord(d[2:3]),6),
					'NDHTSTYP' : ord(d[3:4]),
					'NDHTFLG2' : ord(d[4:5]),
					'NDHT2DFT' : self.get_bit(ord(d[4:5]),7),
					'NDHT2MLO' : self.get_bit(ord(d[4:5]),5),
					'NDHT2SHI' : self.get_bit(ord(d[4:5]),4),
					'NDHT2TRS' : self.get_bit(ord(d[4:5]),3),
					'NDHT2SUS' : self.get_bit(ord(d[4:5]),2),
					'NDHT2RMT' : self.get_bit(ord(d[4:5]),1),
					'NDHTPOEX' : ord(d[5:6]),
					'RESERVED' : d[6:8],
					'NDHTSECL' : self.EbcdicToAscii(d[8:16]),
					'NDHTCNOD' : self.EbcdicToAscii(d[16:24]),
					'NDHTSUSR' : self.EbcdicToAscii(d[24:32]),
					'NDHTSNOD' : self.EbcdicToAscii(d[32:40]),
					'NDHTSGRP' : self.EbcdicToAscii(d[40:48]),
					'NDHTPOEN' : self.EbcdicToAscii(d[48:56]),
					'RESERVED' : self.EbcdicToAscii(d[56:64]),
					'NDHTOUSR' : self.EbcdicToAscii(d[64:72]),
					'NDHTOGRP' : self.EbcdicToAscii(d[72:80]),
				} )
				d = d[job['NDHTLEN']:]


		return job



	def job_headers(self, d):
		self.msg("Job header")

		job = {
			'NJHLEN' : struct.unpack(">H",d[0:2])[0],
			'NJHFLAGS': d[2:3],
			'NJHSEQ': d[3:4]
			}

		self.msg("Length {0} vs actual {1}".format(job['NJHLEN'], len(d)))
		#Job Header General Section
		d = d[4:]
		header = d[2:3]
		length = struct.unpack(">H",d[0:2])[0]

		self.msg("Type: {0}".format(header))
		self.msg(self.phex(d))
		job.update( {
		'NJHGLEN' : length,
		'NJHGTYPE' : header,
		'NJHGMOD' : d[3:4],
		'NJHGJID' : struct.unpack(">h",d[4:6])[0], # Job identifier
		'NJHGJCLS' : self.EbcdicToAscii(d[6:7]), # Job class
		'NJHGMCLS' : self.EbcdicToAscii(d[7:8]), # Message class
		'NJHGFLG1' : ord(d[8:9]),
		'NJHGF1PR' : self.get_bit(ord(d[8:9]),7),
		'NJHGF1CF' : self.get_bit(ord(d[8:9]),3),
		'NJHGF1CA' : self.get_bit(ord(d[8:9]),2),
		'NJHGF1PE' : self.get_bit(ord(d[8:9]),1),
		'NJHGF1NE' : self.get_bit(ord(d[8:9]),0),
		'NJHGPRIO' : ord(d[9:10]),
		'NJHGORGQ' : d[10:11],
		'NJHGJCPY' : d[11:12],
		'NJHGLNCT' : d[12:13],
		# d[13] = Reserved for IBM use
		'NJHGHOPS' : d[14:16],
		'NJHGACCT' : self.EbcdicToAscii(d[16:24]),
		'NJHGJNAM' : self.EbcdicToAscii(d[24:32]),
		'NJHGUSID' : self.EbcdicToAscii(d[32:40]),
		'NJHGPASS' : self.EbcdicToAscii(d[40:48]),
		'NJHGNPAS' : self.EbcdicToAscii(d[48:56]),
		'NJHGETS'  : d[56:64],
		'NJHGORGN' : self.EbcdicToAscii(d[64:72]),
		'NJHGORGR' : self.EbcdicToAscii(d[72:80]),
		'NJHGXEQN' : self.EbcdicToAscii(d[80:88]),
		'NJHGXEQU' : self.EbcdicToAscii(d[88:96]),
		'NJHGPRTN' : self.EbcdicToAscii(d[96:104]),
		'NJHGPRTR' : self.EbcdicToAscii(d[104:112]),
		'NJHGPUNN' : self.EbcdicToAscii(d[112:120]),
		'NJHGPUNR' : self.EbcdicToAscii(d[120:128]),
		'NJHGFORM' : self.EbcdicToAscii(d[128:136]),
		'NJHGICRD' : struct.unpack(">i",d[136:140])[0],
		'NJHGETIM' : struct.unpack(">i",d[140:144])[0],
		'NJHGELIN' : struct.unpack(">i",d[144:148])[0],
		'NJHGECRD' : struct.unpack(">i",d[148:152])[0],
		'NJHGPRGN' : self.EbcdicToAscii(d[152:172]),
		'NJHGROOM' : self.EbcdicToAscii(d[172:180]),
		'NJHGDEPT' : self.EbcdicToAscii(d[180:188]),
		'NJHGBLDG' : self.EbcdicToAscii(d[188:196]),
		'NJHGNREC' : struct.unpack(">i",d[196:200])[0],
		'NJHGJNO' : struct.unpack(">i",d[200:204])[0],
		'NJHGNTYN' : self.EbcdicToAscii(d[204:212])
		} )

		self.msg("Msg Class: {0}".format(job['NJHGMCLS']))
		self.msg("Job class: {0}".format(job['NJHGJCLS']))
		self.msg("Accounting: {0}".format(job['NJHGACCT']))
		self.msg("Job Name: {0}".format(job['NJHGJNAM']))
		self.msg("UserID: {0}".format(job['NJHGUSID']))
		self.msg("Origin Node: {0}".format(job['NJHGORGN']))
		self.msg("Node User ID: {0}".format(job['NJHGORGR']))
		self.msg("Execution Node: {0}".format(job['NJHGXEQN']))
		d = d[length:]

		while len(d) > 1:
			self.msg("Current Remaining: {0}".format(len(d)))
			self.msg(self.phex(d))
			header = d[2:3]
			if header == b"\x8A":
				self.msg("Scheduling Section of the Job Header")
				job['NJHELEN'] = struct.unpack(">h",d[0:2])[0]
				job['NJHETYPE'] = d[2:3]
				job['NJHEMOD'] = d[3:4]
				job['NJHEPAGE'] = struct.unpack(">i",d[4:8])[0]
				job['NJHEBYTE'] = struct.unpack(">i",d[8:12])[0]
				d = d[job['NJHELEN']:]
			elif header == b"\x8C":
				self.msg("Security Section of the Job Header")
				job['NJHTLEN'] = struct.unpack(">h",d[0:2])[0]
				job['NJHTTYPE'] = d[2:3]
				job['NJHTMOD'] = d[3:4]
				job['NJHTLENP'] = struct.unpack(">h",d[4:6])[0]
				job['NJHTFLG0'] = d[6:7]
				#d[7] is reserved
				d = d[8:]
				job['NJHTLENT'] = struct.unpack("b",d[0:1])[0]
				job['NJHTVERS'] = struct.unpack("b",d[1:2])[0]
				job['NJHTFLG1'] = d[2:3]
				job['NJHTSTYP'] = d[3:4]
				job['NJHTFLG2'] = d[4:5]
				job['NJHTPOEX'] = d[5:6]
				#d[6:8] is reserved for IBM?
				job['NJHTSECL'] = self.EbcdicToAscii(d[8:16])
				job['NJHTCNOD'] = self.EbcdicToAscii(d[16:24])
				job['NJHTSUSR'] = self.EbcdicToAscii(d[24:32])
				job['NJHTSNOD'] = self.EbcdicToAscii(d[32:40])
				job['NJHTSGRP'] = self.EbcdicToAscii(d[40:48])
				job['NJHTPOEN'] = self.EbcdicToAscii(d[48:56])
				# Reserved: d[56:64]
				job['NJHTOUSR'] = self.EbcdicToAscii(d[64:72])
				job['NJHTOGRP'] = self.EbcdicToAscii(d[72:80])
				d = d[job['NJHTLENT']:]
			elif header == b"\x8D":
				self.msg("Job Accounting Section")
				self.msg(self.phex(d))
				job['NJHALEN'] = struct.unpack(">h",d[0:2])[0]
				job['NJHATYPE'] = header
				job['NJHAMOD'] = d[3:4]
				job['NJHAOFFS'] = struct.unpack(">h",d[4:6])[0]
				job['NJHAFLG1'] = d[6:7]
				job['NJHAJLEN'] = d[8:8+job['NJHAOFFS']]
				#These aren't document very well
				job['NJHARecords'] = ord(d[8:9])
				job['NJHATotal'] = ord(d[9:10])
				job['NJHARecNum'] = ord(d[10:11])
				job['NJHARecLen'] = ord(d[11:12])
				job['NJHAJAC1'] = self.EbcdicToAscii(d[12:12+job['NJHARecLen']])
				d = d[job['NJHALEN']:]

			elif header == b"\x84":
				self.msg("JES2 Section of the Job Header")
				job['NJH2LEN'] = struct.unpack(">h",d[0:2])[0]
				job['NJH2TYPE'] = d[2:3]
				job['NJH2MOD'] = d[3:4]
				job['NJH2FLG1'] = d[4:5]
				job['NJH2ACCT'] = d[8:12]
				job['NJH2USID'] = d[12:20]
				job['NJH2USR'] = d[20:28]
				job['NJH2GRP'] = d[28:36]
				job['NJH2SUSR'] = d[36:44]
				job['NJH2SGRP'] = d[44:52]
				d = d[job['NJH2LEN']:]
		return job

	def job_footers(self, d):
		self.msg("Job Trailer")
		job = {
			'NJTLEN'  : struct.unpack(">H",d[0:2])[0],
			'NJTFLAGS': d[2:3],
			'NJTSEQ'  : d[3:4]
			}
		self.msg("Total Length: {0}".format(job['NJTLEN']))
		d = d[4:]
		job.update( {
			'NJTGLEN'  : struct.unpack(">h",d[0:2])[0],
			'NJTGTYPE' : ord(d[2:3]),
			'NJTGMOD'  : ord(d[3:4]),
			'NJTGFLG1' : d[4:5],
			'NJTGXCLS' : d[5:6],
			'NJTGSTRT' : d[8:16],
			'NJTGSTOP' : d[16:24],
			'NJTGALIN' : struct.unpack(">i",d[28:32])[0],
			'NJTGACRD' : struct.unpack(">i",d[32:36])[0],
			'NJTGIXPR' : ord(d[40:41]),
			'NJTGAXPR' : ord(d[41:42]),
			'NJTGIOPR' : ord(d[42:43]),
			'NJTGAOPR' : ord(d[43:44]),
			'NJTGCOMP' : ord(d[44:45])
			} )
		return job

	def process_nmr(self, packet):
		self.msg('Processing Operator command/console message')
		d = packet['Data']

		record = {}
		# From http://www-01.ibm.com/support/knowledgecenter/SSB27U_5.4.0/com.ibm.zvm.v54.dmta7/hnmr.htm
		#NMRFLAG
		#record['NMRFLAG'] = ord(d[0])
		record['NMRFLAG'] = d[0:1]
		#NMRFLAGC EQU	B'10000000'		NMRMSG contains a command
	#NMRFLAGW EQU	B'01000000'		NMROUT has JES2 RMT number
	#NMRFLAGT EQU	B'00100000'		NMROUT has user ID
	#NMRFLAGU EQU	B'00010000'		NMROUT has UCMID information
	#NMRFLAGR EQU	B'00001000'		Console is only remote authorized
	#NMRFLAGJ EQU	B'00000100'		Console not job authorized
	#NMRFLAGD EQU	B'00000010'		Console not device authorized
	#NMRFLAGS EQU	B'00000001'		Console not system authorized

		record.update( {
			'NMRFLAGC' : self.get_bit(record['NMRFLAG'],7),
			'NMRFLAGW' : self.get_bit(record['NMRFLAG'],6),
			'NMRFLAGT' : self.get_bit(record['NMRFLAG'],5),
			'NMRFLAGU' : self.get_bit(record['NMRFLAG'],4),
			'NMRFLAGR' : self.get_bit(record['NMRFLAG'],3),
			'NMRFLAGJ' : self.get_bit(record['NMRFLAG'],2),
			'NMRFLAGD' : self.get_bit(record['NMRFLAG'],1),
			'NMRFLAGS' : self.get_bit(record['NMRFLAG'],0),
		#   'NMRLEVEL' : (d[1] & 0xF0). to_bytes(1,"big"), 			
			'NMRLEVEL' : my_to_bytes(d[1] & 0xF0),
		#	'NMRPRIO'  : (d[1] & 0x0F).to_bytes(1,"big"),
			'NMRPRIO'  : my_to_bytes(d[1] & 0x0F),	
			'NMRTYPE'  : d[2:3],
				#NMRTYPE
			#NMRTYPEX EQU	B'11110000'		Reserved bits
			#NMRTYPED EQU	B'00000001'		DOM (not supported)
			#NMRTYPEF EQU	B'00000010'		Formatted command in NMRMSG
			#NMRTYPET EQU	B'00000100'		Msg text only in NMRMSG
			#NMRTYPE4 EQU	B'00001000'		Msg text contains control info
			'NMRTYPEX' : my_to_bytes(d[2] & 0xF0),
		#	'NMRTYPEX' : (d[2] & 0xF0).to_bytes(1,"big"),
			'NMRTYPED' : self.get_bit(d[2:3], 0),
			'NMRTYPEF' : self.get_bit(d[2:3], 1),
			'NMRTYPET' : self.get_bit(d[2:3], 2),
			'NMRTYPE4' : self.get_bit(d[2:3], 3),
			'NMRML'	   : d[3:4],  #Length of the message
			'NMRTONOD' : self.EbcdicToAscii(d[4:12]),
			'NMRFMQUL' : d[12],
			'NMROUT'   : d[13:21],
			'NMRFMNOD' : self.EbcdicToAscii(d[21:29]),
			'NMRTOQUL' : d[29]
		} )


		if not(record['NMRFLAGW'] or record['NMRFLAGT'] or record['NMRFLAGU']):
			self.msg("Logical Routed Message")
			#NMROUT format for logical routed msgs
			# 0 NMRDESC  MCS descriptor codes
			# 2 NMRROUT  MCS console routings
			# 4 NMRDOMID MCS DOM ID
			#self.msg("[NMROUT] MCS routing code: %r", record['NMROUT'])
			record['NMRDESC']  = record['NMROUT'][0:2]
			record['NMRROUT']  = record['NMROUT'][2:4]
			record['NMRDOMID'] = record['NMROUT'][4:]
		elif not(record['NMRFLAGW'] or record['NMRFLAGT']) and record['NMRFLAGU']:
			self.msg("UCMID Message")
			#NMROUT format for UCMID messages
			#
			# 0 NMRUCM   MCS console ID
			# 1 NMRUCMA  MCS console area
			# 2 NMRLINET Line type for MLWTO
			# 4		 Spacer
			record['NMRUCM']   = record['NMROUT'][0:1]
			record['NMRUCMA']  = record['NMROUT'][1:2]
			# Line Types:
			# 0x8000 = First Line
			# 0x2000 = Middle Line(s)
			# 0x3000 = Last Line
			# 0x9000 = Only line
			self.msg("NMROUT: {0}".format(self.phex(record['NMROUT'])))
			record['NMRLINET'] = struct.unpack("h",record['NMROUT'][2:4])[0]
			self.msg("[NMROUT] MCS Console ID: {0}".format(record['NMRUCM']))
			self.msg("[NMROUT] Line Type: {0} {1}".format(record['NMRLINET'], self.phex(record['NMROUT'][2:4])))
		elif not(record['NMRFLAGW'] or record['NMRFLAGU']) and record['NMRFLAGT']:
			self.msg("User Message")
			# NMROUT format for user messages (NMRFLAGT on and NMRFLAGC off)
			# NMRUSER Receiving user ID
			record['NMRUSER'] = self.EbcdicToAscii(record['NMROUT'])
			self.msg("[NMROUT] UserID: {0}".format(record['NMRUSER']))
		elif not(record['NMRFLAGT'] or record['NMRFLAGU']) and record['NMRFLAGW']:
			# NMROUT format for remote messages
			# 0 NMRRMT Remote name 'RNNNNNNN'
			self.msg("[NMROUT] Remote Workstation ID: {0}".format(record['NMROUT']))
			record['NMRRMT'] = record['NMROUT']
		elif (record['NMRFLAGT'] or record['NMRFLAGW']) and not record['NMRFLAGU']:
			self.msg("[NMROUT] User ID / Remove Workstation ID: {0}".format(record['NMROUT']))


		d = d[30:]
		#Determining NMR Contents
		if record['NMRFLAGC']:
			if record['NMRTYPEF']:
				self.msg("Type: Formatted Command")
				#TO DO
			else:
				self.msg("Type: Unformatted Command")
				#TO DO
				record['NMRMSG'] = self.EbcdicToAscii(d[:record['NMRML'][0]])
		else:
			self.msg("Type: Message")
			# Here's the actual contents of the message!
			record['NMRMSG'] = self.EbcdicToAscii(d[:record['NMRML'][0]])
			if not(record['NMRTYPE4'] or record['NMRTYPET']):
				record['timestamp'] = record['NMRMSG'][0:8]
			elif record['NMRTYPE4'] and not record['NMRTYPET']:
				record['timestamp'] = record['NMRMSG'][0:8]
				record['NMRECSID'] = record['NMRMSG'][8:16]
			elif record['NMRTYPE4'] and record['NMRTYPET']:
				record['NMRECSID'] = record['NMRMSG'][0:8]

		return record

	def get_bit(self, Bbyte, i):
		if (type(Bbyte) != bytes):
			if (type(Bbyte) == int):
				val = Bbyte
		else:
##			val = int.from_bytes(Bbyte,"big")
			val = my_from_bytes(Bbyte)
		val = ((val & (1 << i)) !=0)
		return (val);

	def hex2ip(self, ip_addr):
		ip = ''
		for i in range(0,len(ip_addr)):
			ip += str(struct.unpack('<B', ip_addr[i])[0])+"."
		return ip[:-1]

	def makeSYSIN_header(self, lines, jobnum, programmer, job_class, msg_class, job_name, acc, userid="ibmuser", group=None, passw=''):
		""" Creates the necesary sections of the job headers for the NJE record """

		userid = str(userid).strip().upper()
		group = '' if group is None else str(group).strip().upper()
		if not re.fullmatch(r"[A-Z0-9@#$]{1,8}", userid):
			raise ValueError("userid must be 1-8 valid RACF name characters")
		if group and not re.fullmatch(r"[A-Z0-9@#$]{1,8}", group):
			raise ValueError("group must be 1-8 valid RACF name characters")

		NJHTSUSR = self.padding(userid)
		NJHTSNOD = self.RHOST
		NJHTSGRP = self.padding(group)
		NJHTOUSR = self.padding(userid)
		NJHTOGRP = self.padding(group)

		nje_header = ( b"\x00\xD4"+ b"\x00" + # Length + NJHGTYPE
			  b"\x00" + #NJHGMOD
			  struct.pack(">h",jobnum) + #NJHGJID Job identifier 2 bytes)
			  self.AsciiToEbcdic(job_class) + #NJHGJCLS
			  self.AsciiToEbcdic(msg_class) + #NJHGMCLS
			   b"\x40" + #NJHGFLG1
			   #chr(9) + #NJHGPRIO
			   b'\x09' +   #NJHGPRIO
			   self.target_node + #NJHGORGQ
			   b"\x01" + #NJHGJCPY
			   b"\x00" + #NJHGLNCT
			   b"\x00" + #Reserved?
			   b"\x00\x00" + #NJHGHOPS
			   b'\x00\x00\x00\x00\x00\x00\x00\x00' + #NJHGACCT
			   self.padding(job_name) + # NJHGJNAM
			   self.padding(userid) + #NJHGUSID
			   #(b"\x00" * 8) +
			   (b"\x00" * 8) + #NJHGPASS
			   (b"\x00" * 8) + #NJHGNPAS
			   #b"\xD0\x1A\xDB\xA9\x15\xE5\x90\x00" + # NJHGETS : STCK Format date. hardcoded to 05-Jan-2016 22:06:08
			   b"\xd0$\xfe\x11\xe1\xea\x10\x00" +
			   self.RHOST + # NJHGORGN
			   self.padding(userid) + #NJHGORGR
			   self.OHOST + #NJHGXEQN
			   (b"\x40" * 8) + #self.padding(userid) + #NJHGXEQU
			   self.RHOST + #NJHGPRTN
			   #(b"\x40" * 8) + # NJHGPRTR
			   self.RHOST + # NJHGPRTR
			   self.RHOST + #NJHGPUNN
			   (b"\x40" * 8) + #NJHGPUNR
			   self.padding('STD') + # NJHGFORM
			   struct.pack(">i",lines) + #NJHGICRD
			   b"\x00\x00\x00\x78" + #NJHGETIM
			   b"\x00\x00\x2E\xE0" + #NJHGELIN
			   b"\x00\x00\x00\x64" + #NJHGECRD
			   (self.AsciiToEbcdic(programmer) + SPACE * (20-len(programmer))) + #NJHGPRGN
			   #(b"\x40" * 20) +
			   (b"\x40" * 8) + #NJHGROOM
			   (b"\x40" * 8) + #NJHGDEPT
			   (b"\x40" * 8) + #NJHGBLDG
			   (b"\x00" * 4) + #NJHGNREC
			   struct.pack(">i", jobnum) + #NJHGJNO
			   self.RHOST #NJHGNTYN
			   #(b"\x00" * 8)
			  )

		#NJH2		   LEN		  TYPE	Remaining items all zeros
		jes2_header = ( b"\x00\x34" + b"\x84" + (b"\x00" * 49)	)

		#NJHE		 LEN		 TYPE	 MOD	  PAGE			 BYTE
		sched_header = b"\x00\x0C" + b"\x8A" + b"\x00" + b"\x00\x00\x00\x28" + b"\x05\xF5\xDD\x18"

		#NJHA		TYPE	 MOD	  OFFS		   FLG1	Reserved
		acc_header = (b"\x8D" + b"\x00" + b"\x00\x00" + b"\x00" + b"\x08" +
							#NJHAJLEN						  NJHAJAC1
#						struct.pack(">h",len(acc) + 2) + b"\x01" + len(acc).to_bytes(1,"big") + self.AsciiToEbcdic(acc) )
						struct.pack(">h",len(acc) + 2) + b"\x01" + my_to_bytes(len(acc)) + self.AsciiToEbcdic(acc) )
		acc_header = struct.pack(">h",len(acc_header) + 2) + acc_header

		# NJHTF0JB is off: this section describes the submitting identity.
		# RACF can propagate that identity into the job owner according to the
		# receiving node's NODES USERJ/GROUPJ profiles.
		sec_prefix = (
			b"\x00\x58" + b"\x8C" + b"\x00" + b"\x00\x04"
			+ b"\x00" + b"\x00"
		)
		# External NJE format (0x40), originating without RACF (0x20), and
		# batch-job security session type (0x07).
		sec_subsec = b"\x50\x01\x60\x07"
		# This client authenticates the NJE node, not the individual RACF user.
		# Mark the supplied identity as default/unverified (0x80) and remotely
		# originated (0x02); the receiving RACF policy decides whether it may be
		# propagated, translated, or rejected.
		sec_subsec += b"\x82"
		# NJHT		POEX	  RESRVD	SECL		 CNOD	   SUSR + SNOD + SGRP
		sec_subsec += (b"\x03" + b"\xC0\x00" + (b"\x00" * 8) + self.RHOST +
					   NJHTSUSR + NJHTSNOD + NJHTSGRP +
					   #POEN	   RESRVD
					   self.padding("INTRDR") + (b"\x00" * 8) )
		# Owner fields mirror the submitting identity. They are assertions only;
		# they do not bypass RACF validation or NODES-class policy.
		self.msg("Setting Target User/Group: {0}/{1}".format(userid.upper(), group.upper()))
		sec_subsec += NJHTOUSR + NJHTOGRP
		sec_header = sec_prefix + sec_subsec

		#NJH		 LEN	   SEQ
		job_prefix = b"\x00\xFD\x00\x80"

		# Because the total combination of headers is always larger than 253 bytes
		# the job_prefix (NJH) is length of 253 with a SEQuence flag identifying remaining sequences
		# we then split the string at 253 bytes (NJE records had a 255 byte limit, 253 + RCB + SRCB = 255)
		# and prepent the second part with another NJH

		#print("len jp:{0} nh:{1} jh:{2} sh:{3} ah:{4} sch:{5}".format(len(job_prefix),len(nje_header),len(jes2_header),len(sched_header),len(acc_header),len(sec_header)))

		header = job_prefix + nje_header + jes2_header + sched_header + acc_header + sec_header
		part1 = header[:253]


		#NJH				   LEN			 SEQ
		part2 = struct.pack(">h",len(header[253:] )+ 4) + b"\x00\x01" + header[253:]

		return part1 + part2

	def makeSYSIN_footer(self):
		""" NJE JOB Footer """
		return (b"\x00\x34\x00\x00") + (b"\x00\x30") + (b"\x00" * 46)

	def makeSCB(self, buf):
		''' Implements SCB compression. Returns a tuple of compressed bytes and
			the number of bytes remaining in buf. '''

	# This version implements compression better than IBM for some reason.

		# String Control Byte				(Pg 123)
		# More information available here:
		# http://www-01.ibm.com/support/knowledgecenter/SSLTBW_2.1.0/com.ibm.zos.v2r1.hasa600/nscb.htm

		self.msg("Compressing {0} bytes using \"String Control Byte\" compression".format(len(buf)))
		self.msg("Raw Message before compression: {0}".format(self.phex(buf)))

		#self.msg("Recieved: %r", self.phex(buf))
		if len(buf) == '':
			return ''
		ebc_space = bytes(" ".encode('EBCDIC-CP-BE')) # byte representation of EBCDIC space (0x40, ascii @ ) 
		processed_bytes = 0
		c = 0
		d = b'' # The compressed data < 252 bytes
		t = b'' # Temp data while we count
#		print(self.phex(buf))
		while len(buf) > 0 and processed_bytes < 253:
			if buf[0:1] == ebc_space and buf[1:2] == ebc_space:
				if c > 0:
#					d += (0xC0 + c).to_bytes(1,"big") + t # If we go straight from repeat char to repeat spaces this creates an extra char
					d += my_to_bytes(0xC0 + c) + t # If we go straight from repeat char to repeat spaces this creates an extra char
				t = b''
				c = 1
				while c < len(buf) and (buf[c:c+1] == ebc_space and (processed_bytes + c < 253)):
					if c == 31: 
						break
					c += 1
#				d += (0x80 + c).to_bytes(1,"big")
				d += my_to_bytes(0x80 + c)
				#self.msg("Repeated %r %i times", buf[0], c)
				buf = buf[c-1:]
				processed_bytes += c
				c = 0
			elif len(buf) > 2 and buf[0:1] == buf[2:3] and buf[0:1] == buf[1:2]:
				if c > 0: 
#					d += (0xC0 + c).to_bytes(1,"big") + t # Same as above. This if fixes that
					d += my_to_bytes(0xC0 + c) + t # Same as above. This if fixes that
				t = b''
				c = 2
				while c < len(buf) and ( buf[c:c+1] == buf[0:1] and (processed_bytes + c < 253) ):
					if c == 31: 
						break
					c += 1
#				d += (0xA0 + c).to_bytes(1,"big") + buf[0:1]
				d += my_to_bytes(0xA0 + c) + buf[0:1]
				buf = buf[c-1:]
				processed_bytes += c
				c = 0
			elif c == 63:
#				d += (0xC0 + c).to_bytes(1,"big") + t
				d += my_to_bytes(0xC0 + c) + t
				t = b''
				processed_bytes += c
				c = 0
			else:
				t += buf[0:1]
				c += 1
				processed_bytes += 1

			buf = buf[1:]
			#print(self.phex(d))
		if c > 0: 
#			d += (0xC0 + c).to_bytes(1,"big") + t
			d += my_to_bytes(0xC0 + c) + t
		self.msg("Total bytes: {0} compressed to {1}".format(processed_bytes, len(d)))
		#self.msg("Remaining bytes: %i", len(buf))
		self.msg("Compressed: {0}".format(self.phex(d)))
		# print(d+b'\x00', len(buf))
		# sys.exit(99)
		return (d+b'\x00', len(buf))

	def compressed(self, RCB_bytes):
		# print(type(RCB_string))
		# print(RCB_string)
		# sys.exit(-3)
		#RCB = ord(RCB_string)
		#RCB = ord(RCB_string)
##		RCB = int.from_bytes(RCB_bytes,"big")
		RCB = my_from_bytes(RCB_bytes)
		if (RCB == 0x9A) or ((RCB & 0x0F) == 0x08) or ((RCB & 0x0F) == 0x09):
			return True
		else:
			return False


	def readSCB(self, data):
		""" readSCB takes in compressed data and processes it until it hits
			a 0x00 byte. It returns a tuple of the decompressed data and
			the ammount of bytes processed. 0x00 represents the end of an
			NJE record """

		# initialize our vars
		buf = b''  #output buffer
		skip = 0
		count = 0
		b = 0      # len of final buffer
		i = 0      # counter
		repeat = False   # identify repeating segments to unpack
		lenData = len(data)
		ebc_space = bytes(" ".encode('EBCDIC-CP-BE')) # byte representation of EBCDIC space (0x40, ascii @ ) 

		for i in range(0,lenData):
			iByte = data[i:i+1] # get current byte
			b += 1              # increment length of final buffer
			if skip > 0:
				skip -= 1
				buf += iByte
				continue
			if repeat:
				#self.msg("Char %r repeats %r times", self.phex(i), count)
				buf += iByte * count
				repeat = False
				continue
			#SCB = ord(i)
##			SCB = int.from_bytes(iByte,"big")
			SCB = my_from_bytes(iByte)
			SCB_type = SCB & 0xC0
			#self.msg("Current Char: %r, Count: %r, Type: %r", self.phex(i), (SCB & 0x3F), self.phex(chr(SCB_type)))
			if SCB_type == 0x00:
				#self.msg("End of Record. Total Processed: %i", b)
				break
			elif SCB_type == 0xC0:
				skip = SCB & 0x3F
				#self.msg("Type 0xC0: %r Uncompressed chars follow", skip)
			elif SCB_type == 0x80:
				#self.msg("Either of type b'101' (chars) or b'100' (blanks aka 0x40): %r", self.phex(i))
				sub_type = SCB & 0xE0
				count = SCB & 0x1F
				if sub_type == 0xA0:
					repeat = True
				else:
					#self.msg("%i spaces added", count)
					buf += ebc_space * count

		self.msg("Decompressed {0} bytes to {1} bytes".format(b, len(buf)))
		return (buf, b)

	def getNMR(self):
		""" Returns NRM an array of dictionaries """
		return NMR

	def getSYSIN(self):
		""" Returns SYSIN an array of dictionaries """
		return SYSIN

	def getSYSOUT(self):
		""" Returns SYSOUT an array of dictionaries """
		return SYSOUT

	def sendMessage(self, message, user=''):
		msg = "Sending Message: " + message
		if user:
			msg += " to user " + user.upper()
		self.msg(msg)
		msg = self.sendNMR(message, False, user)
		time.sleep(5)
#		self.signoff()

	def sendCommand(self, command, clear=True, wait=5.0):
		"""Send an operator command (NMR) and return the reply text.

		clear=True (default) drops previous NMR replies so only this command's
		responses are returned. Pass clear=False to keep and include history.
		wait: seconds to collect replies (multi-packet responses).

		If the session sat idle, a heartbeat is sent first (see idle_heartbeat).
		Long idle links are often dropped by JES2/AT-TLS/TCP — reconnect if
		this returns False with a dead session.
		"""
		self.msg("Sending command: {0}".format(command))
		if not self._ensure_session():
			self.msg("Session not alive (idle timeout or peer closed); reconnect")
			return False
		if clear:
			NMR.clear()
		try:
			self.sendNMR(command, True)
		except OSError as e:
			self.msg("sendCommand send failed: {0}".format(e))
			return False

		# Collect replies; keep draining briefly after the first NMR arrives
		# so multi-line console output is not left sitting for the next call.
		deadline = time.time() + wait
		got_reply = False
		while time.time() < deadline:
			if not self.connected:
				break
			timeout = min(0.5, max(0.05, deadline - time.time()))
			if not self._process_inbound(timeout=timeout):
				if got_reply:
					break
				continue
			if NMR:
				got_reply = True
				# short quiet period for trailing lines, then stop
				self._drain_inbound(idle=0.25, max_rounds=5)
				break

		message = ''
		for record in self.getNMR():
			for i in record:
				self.msg("record[{0}]: {1}".format(i, record[i]))
			if 'NMRMSG' in record:
				message += record['NMRMSG'].decode('ascii') + "\n"
		if len(message) <= 0:
			return False
		else:
			return message

	def sendJCL(self, filename, userid='ibmuser', group=None, wait_for_sysout=True):
		"""Send a JCL file, optionally waiting for a complete SYSOUT stream."""
		self.msg("Processing JCL file")
		completed_jobs_before = len(self._completed_sysout_jobs)

		with open (filename, "r") as myfile:
			data=myfile.readlines()

		for i in range(0,len(data)):
			if i == 0:
				header = data[i].strip()
				continue
			if data[i][2] == " ":
				header += data[i][3:].strip("\n")
			else:
				break


		job = header.strip()[2:10]
		acc = header[header.find("(")+1:header.find(")")]
		quoted = re.compile("(?<=')[^']+(?=')")
		prog = quoted.findall(header)[0]

		self.msg("Creating SYSIN Headers with the following:")
		self.msg("Job Name: {0}".format(job))
		self.msg("Accounting: {0}".format(acc))
		self.msg("Programmer: {0}".format(prog))
		self.msg("UserID: {0}".format(userid))
		self.msg("Group: {0}".format(group))

		jcl = []
		num = self._next_nje_job_number
		self._next_nje_job_number = 1 if num >= 32767 else num + 1
		jcl.append(
			data[0].strip("\n")
			+ " " * (72 - len(data[0].strip("\n")))
			+ "JOB{0:05d}".format(num)
		)
		jcl += data[1:]
		self.msg("Job Number: {0}".format(num))
		jcl_class = "A"
		msg_class = "K"
		nje_jcl = self.makeSYSIN_header(len(jcl), num, prog, jcl_class, msg_class, job, acc, userid, group)
		records = []
		records.append({'RCB':b"\x98",'SRCB':b"\xC0", 'Data':nje_jcl})
		for line in jcl:
			self.msg("[JCL] Len {0}: {1}".format(len(line.strip("\n")), line.strip("\n")))
			records.append({'RCB':b"\x98",'SRCB':b"\x80", 'Data':b"\x50"+ self.AsciiToEbcdic(line.strip("\n"))})

		records.append({'RCB':b"\x98",'SRCB':b"\xD0", 'Data':self.makeSYSIN_footer()})

		# Step 1: Tell the mainframe we're making a stream
		self.request_stream()
		self.records = self.processData(self.getData())
		self.process_RCB()
		# Step 2: Send the stream (SYSIN)
		self.sendNJE_multiple(records)
		# Step 3: Close the stream
		self.sendNJE(b"\x98", b"\x00",b"\x00\x00")
		self.records = self.processData(self.getData())
		self.process_RCB()

		if wait_for_sysout:
			while not self._sysout_job_completed_since(
				num, job, completed_jobs_before
			):
				self.records = self.processData(self.getData())
				self.process_RCB()
				if not self.connected:
					raise ConnectionError(
						"NJE peer disconnected while waiting for complete SYSOUT"
					)
#		self.signoff()

	def upload_text(self, local_path, dataset, userid='ibmuser', group=None,
			create=False, recfm='FB', lrecl=80, blksize=0,
			primary=5, secondary=5, unit='SYSDA', long_lines='error',
			wait_for_sysout=True):
		"""Upload an ASCII text file through NJE using an IEBGENER job.

		The destination may be an existing sequential data set or an existing
		PDS/PDSE member.  Set create=True to allocate a new sequential data set.
		If group is omitted, RACF may select the propagated user's default group.
		Existing sendJCL() callers retain their original wait-for-SYSOUT behavior.
		"""
		dataset = str(dataset).strip().upper()
		dsn_pattern = (
			r"[A-Z@#$][A-Z0-9@#$-]{0,7}"
			r"(?:\.[A-Z@#$][A-Z0-9@#$-]{0,7})*"
		)
		member_match = re.fullmatch(
			r"(" + dsn_pattern + r")\(([A-Z@#$][A-Z0-9@#$]{0,7})\)",
			dataset
		)
		if member_match:
			base_dsn = member_match.group(1)
		else:
			base_dsn = dataset
		if not re.fullmatch(dsn_pattern, base_dsn):
			raise ValueError("invalid z/OS data set name: {0}".format(dataset))
		if len(base_dsn) > 44:
			raise ValueError("z/OS data set name exceeds 44 characters")
		if create and member_match:
			raise ValueError("create=True only supports a sequential data set")

		recfm = str(recfm).upper()
		if recfm not in ('F', 'FB'):
			raise ValueError("upload_text currently supports RECFM F or FB")
		if not isinstance(lrecl, int) or not 1 <= lrecl <= 80:
			raise ValueError("lrecl must be between 1 and 80")
		if long_lines not in ('error', 'wrap', 'truncate'):
			raise ValueError("long_lines must be 'error', 'wrap', or 'truncate'")

		with open(local_path, 'r', encoding='ascii', newline=None) as source:
			source_lines = source.read().splitlines()

		data_lines = []
		for line_number, line in enumerate(source_lines, 1):
			if len(line) <= lrecl:
				data_lines.append(line)
			elif long_lines == 'truncate':
				data_lines.append(line[:lrecl])
			elif long_lines == 'wrap':
				data_lines.extend(
					line[offset:offset + lrecl]
					for offset in range(0, len(line), lrecl)
				)
			else:
				raise ValueError(
					"line {0} is {1} characters; LRECL is {2}".format(
						line_number, len(line), lrecl
					)
				)

		# DLM must be exactly two characters.  Select one that cannot be
		# mistaken for a data record in this particular input file.
		data_set = set(data_lines)
		delimiter = None
		for first in 'ZQXWVUTSRPONMLKJIHGFEDCBA':
			for second in 'ZQXWVUTSRPONMLKJIHGFEDCBA0123456789':
				candidate = first + second
				if candidate not in data_set:
					delimiter = candidate
					break
			if delimiter:
				break
		if delimiter is None:
			raise ValueError("could not select a safe two-character JCL delimiter")

		jcl_lines = [
			"//NJEUPLD JOB (NJE),'NJELIB',CLASS=A,MSGCLASS=H",
			"//COPY     EXEC PGM=IEBGENER",
			"//SYSPRINT DD SYSOUT=*",
		]
		if create:
			for name, value in (
				('primary', primary), ('secondary', secondary),
				('blksize', blksize)
			):
				if not isinstance(value, int) or value < 0:
					raise ValueError("{0} must be a non-negative integer".format(name))
			if primary == 0:
				raise ValueError("primary must be greater than zero")
			unit = str(unit).strip().upper()
			if not re.fullmatch(r"[A-Z0-9@#$]{1,8}", unit):
				raise ValueError("invalid UNIT value")
			jcl_lines.extend([
				"//SYSUT2   DD DSN={0},".format(dataset),
				"//            DISP=(NEW,CATLG,DELETE),UNIT={0},".format(unit),
				"//            SPACE=(TRK,({0},{1})),".format(primary, secondary),
				"//            DCB=(RECFM={0},LRECL={1},BLKSIZE={2})".format(
					recfm, lrecl, blksize
				),
			])
		else:
			jcl_lines.append("//SYSUT2   DD DSN={0},DISP=OLD".format(dataset))

		jcl_lines.extend([
			"//SYSIN    DD DUMMY",
			"//SYSUT1   DD DATA,DLM={0}".format(delimiter),
		])
		jcl_lines.extend(data_lines)
		jcl_lines.append(delimiter)

		for line_number, line in enumerate(jcl_lines, 1):
			if len(line) > 80:
				raise ValueError(
					"generated JCL record {0} exceeds 80 columns: {1}".format(
						line_number, line
					)
				)

		temp_name = None
		try:
			with tempfile.NamedTemporaryFile(
				mode='w', encoding='ascii', newline='\n',
				prefix='njelib-upload-', suffix='.jcl', delete=False
			) as temp_jcl:
				temp_name = temp_jcl.name
				for line in jcl_lines:
					temp_jcl.write(line + '\n')
			self.sendJCL(
				temp_name, userid=userid, group=group,
				wait_for_sysout=wait_for_sysout
			)
		finally:
			if temp_name:
				try:
					os.unlink(temp_name)
				except OSError:
					pass

		return {
			'dataset': dataset,
			'records': len(data_lines),
			'lrecl': lrecl,
			'recfm': recfm,
			'created': bool(create),
			'wait_for_sysout': bool(wait_for_sysout),
		}

	def dumbClient(self):
		""" Connects to an NJE server and does nothing """
		self.msg("Starting Dumb Client")
		while True:
			self.records = self.processData(self.getData())
			self.process_RCB()

	def analyze(self, njefile):
		with open (njefile, "r") as myfile:
			data=myfile.read()
		self.msg("Length: {0}".format(len(data)))
		self.msg('Raw Bytes as Hex:')
		self.msg(" >> {0}".format(self.phex(data)))
		self.records = self.processData(data)
		self.process_RCB()
		for i in self.records:
			for x in i:
				self.msg("nje.records["+x+"] : {0}".format(i[x]))

def test():
	"""Test program for njelib.

	Usage: python njelib.py [-d] ... [host [port]] [RHOST OHOST]

	Default host is localhost; default port is 175.

	"""
	debuglevel = 1

	while sys.argv[1:] and sys.argv[1] == '-d':
		debuglevel = debuglevel+1
		del sys.argv[1]

	host = 'localhost'
	if sys.argv[1:]:
		host = sys.argv[1]

	port = 3117
	if sys.argv[2:]:
		portstr = sys.argv[2]
		try:
			port = int(portstr)
		except ValueError:
			port = socket.getservbyname(portstr, 'tcp')

	rhost = 'ZM15'
	ohost = 'CLASS'
	if sys.argv[3:]:
		rhost = sys.argv[3]
		ohost = sys.argv[4]

	password = ''
	if sys.argv[5:]:
		password = sys.argv[5]

	nje = NJE(ohost,rhost)
	nje.set_debuglevel(debuglevel)
	t = nje.session(host=host,port=port, timeout=2, password=password)

	if t:
		print("[+] Connection Successful")
	else:
		print("[!] Connection Failed")

if __name__ == '__main__':
	test()
