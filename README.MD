# NJE Python Library

# What the hell is NJE?

NJE is known as 'Network Job Entry.' It is used by mainframes all over the world to communicate seamlessly with one another. It allows for the sending on files, jobs, system control, etc.

The easiest way to explain NJE is using an example. Let's say I'm a super huge mega corporation. I have offices in Washington, DC and New York NY and each have their own mainframe (DC is where we process payroll, New York is where we process insurance claims). Our IT center is headquartered in New York and we don't want to hire more people than we need in DC so we setup NJE with the following in a config (JES2 Parmlib for you pedantics) file:

```
 NJEDEF   NODENUM=2,
          OWNNODE=1,
          LINENUM=1

 NODE(1)  NAME=NEWYORK
 NODE(2)  NAME=WASHDC

 NETSRV(1) SOCKET=LOCAL
 LINE(1)  UNIT=TCPIP
 SOCKET(WASHDC) NODE=2,
         IPADDR=33.1.3.37

```

Then, from NEWYORK, we enable it and connect with these commands:

```
$S NETSERV1
$S LINE1
$S N,LINE1,WASHDC
```

Now the two mainframes can talk to one another over TCPIP.

**NOTE**: The above isn't secure. It isn't using SSL and there's no password required to connect.

With that setup you can now send commands to one another through whats called 'NMRs.' For example, if we wanted to display the current NJE setup at NEWYORK (from WASHDC) i would issue the `$D NJEDEF` command and get the reply:

```
$HASP831 NJEDEF
$HASP831 NJEDEF  OWNNAME=NEWYORK,OWNNODE=1,CONNECT=(YES,10),
$HASP831         DELAY=120,HDRBUF=(LIMIT=10,WARN=80,FREE=10),
$HASP831         JRNUM=1,JTNUM=1,SRNUM=1,STNUM=1,LINENUM=1,
$HASP831         MAILMSG=NO,MAXHOP=0,NODENUM=2,PATH=1,
$HASP831         RESTMAX=262136000,RESTNODE=100,RESTTOL=0,
$HASP831         TIMETOL=1440
```
But being able to issue commands isn't all NJE can do. The most important part is being able to submit jobs and transfer files. Jobs on the mainframe are scripts with input and output directives. To send a job from Washington DC (WASHDC) to New York (NEWYORK) we place an *execution* line (e.g. `/*XEQ NEWYORK`) in the job.

```
 //H4CKRNJE JOB (1234567),'ABC 123',CLASS=A,
 //             MSGLEVEL=(0,0),MSGCLASS=K,NOTIFY=&SYSUID
 /*XEQ    NEWYORK
 //TSOCMD   EXEC  PGM=IKJEFT01
 //SYSTSPRT DD    SYSOUT=*
 //SYSOUT   DD    SYSOUT=*
 //SYSTSIN  DD    *
   TIME
/*
```

When we run this job (aka submit it to be processed) JES2 will read the `/*XEQ` line and send it to be processed at NEWYORK instead of locally. You can determine (if you have the rights) what nodes exist through the SDSF command `NODE` or through JES2 `$D NODE` or by reading the JES2 config (parmlib) file or by reading JCL we find on the system, sharepoint, wherever.


Finally, using XMIT you can also transfer files between two systems. So if you have a library on the development system you want to move to production you could use XMIT in stead of FTP. Keep in mind, however, that if SSL isn't turned on you'll be sending this data in clear text (hint hint PCI assessors).

## Local Nodes
Once a system is declared in NJE and connected it still won't be able to submit jobs between one system and another. There's so many different ways to declare NJE to your security product that I'm only going to focus on the concept of local nodes in RACF. In RACF you declare nodes to be trusted and any jobs coming from that system will be treated as though they came from the local system (user permission wise). This is because the userid is assumed to be validated at the node its coming from. Read the comments in the `makeSYSIN_header()` function to see what this is and what's important. Specifically the `NJHTFLG2`, `NJHTOUSR` and `NJHTOGRP` header items.

# Using this Library
This library connects to a mainframe serving up NJE and pretends to be mainframe. NJE runs on port 175 or 2252(ssl) and (generally) runs over TCPIP. To use NJE all you need are the **OHOST** and **RHOST** names.
* **OHOST**: Target System node name (could be hostname but not always). In our examples, NEWYORK is the OHOST.
* **RHOST**: The system we're pretending to be. In these examples WASHDC is the RHOST.

First we create an NJE object:
```python
import njelib
nje = njelib.NJE("WASHDC","NEWYORK")
```
Now we need to connect to a mainframe:
```python
connected = nje.session(host="3.1.33.7",port=175)

if not connected:
   print "That didn't work"
   return
```
the `session()` function will return `True` if the connection is successful and `False` if it failed for any reason. This script tries to initiate an SSL connection first and falls back to unencrypted if that fails.

Notice that this library is silent unless you turn on debugging with:
```python
nje.set_debuglevel(1)
```
Once we're connected we can issue commands, send messages and/or submit JCL:
```python
#send a command
Reply = nje.sendCommand(args.command)
print Reply

#send a message to someone
nje.sendMessage("MESS WITH THE BEST DIE LIKE THE REST", "plague")

#send a message to the master console
nje.sendMessage("ARF ARF")

#send a JCL file as a specific user
nje.sendJCL("cookie.jcl", "plague")
```
when you submit JCL/commands you'll get messages (aka NMR) and/or SYSOUT (job output) back. To access that information you can access dictionaries which collect all the headers, footers etc as described in the NJE documentation through a handful of functions:
* `getNMR()` - returns a list of dictionaries with message headers and message contents
* `getSYSIN()` - returns a list of dictionaries with job/dataset headers/footers and dataset contents
* `getSYSOUT()` - returns a list of dictionaries with job/dataset headers/footers and dataset contents

```python
#send JCL
nje.sendJCL("cookie.jcl", "plague")
#Print any messages
for record in nje.getNMR():
   if 'NMRUSER' in record:
      print "[+] User Message"
      print "[+] To User:", record['NMRUSER']
      print "[+] Message:", record['NMRMSG']
   elif 'NMRMSG' in record :
      print "[+] Message:", record['NMRMSG']

#Prints any data we've received
print "[+] Records in SYSOUT:"
for record in nje.getSYSOUT():
    if 'Record' in record:
        print record['Record']
```
## Offline Analysis
Using Wireshark you can easily capture NJE records flying across the network. Unfortunately there's currently no formatting available for NJE (future project perhaps). Using this library however, and the raw data extracted from Wireshark you can assess what was sent across the wires. You can use the **set_offline()**

```
python
import njelib
nje = njelib.NJE()
nje.set_debuglevel(1)
nje.set_offline()
nje.analyze('./wireshark/nje.packet')
```

# TLS support with certificates
There is some support for TLS with certificates.  You need to specify the certificate pem file, the certficate key pem file, and the pem file with the certificate authority certificate.

```python
 import njelib
 import sys
 nje = njelib.NJE("N50","S0W1")

 nje.setTLS(certfile="location of certfile.pem",
           keyfile="location of certfile.key.pem",
           cafile="location of ca.pem")

 connected = nje.session(host="10.1.1.2",port=2252,timeout=1)

```

# What's missing?
Currently there's no support for XMIT (sending/recieving of dataset) but with the current library as is it shouldn't be too hard to implement.

# Credits/Sources:
To get a LOT more information about NJE than you ever wanted to know you can check out the documentation about the protocol in IBM book **HAS2A620**: **Network Job Entry: Formats and Protocols**. Available Here: http://publibz.boulder.ibm.com/epubs/pdf/has2a620.pdf. I also used the [online documentation](http://www-01.ibm.com/support/knowledgecenter/SSLTBW_2.1.0/com.ibm.zos.v2r1.hasa600/toc.htm) frequently and on top of that sometimes the z/VM documentation was a little  clearer (for example [this entry on NMR headers and contents](http://www-01.ibm.com/support/knowledgecenter/SSB27U_5.4.0/com.ibm.zvm.v54.dmta7/hnmr.htm)).

Some notes/thoughts about the documentation:
- IBM did a great job documenting everything (this is not sarcasm, nor was that)
- TCP is a Non-SNA Buffer Format (labelled BCS sometimes)
- The sections are described in alphabetical (not always!) order, not in the order within the packet being sent/received
- My SCB compression algorithm beats IBMs by 2 bytes!
- Not everything is documented well or completely (but I'm just grateful the documentation was available) for example accounting headers

# Included Files:
There's a bunch of files included with this library to provide examples on usage:
* **iNJEctor.py**: A script created for DEFCON 23 to send messages and commands to a target node.
* **analyze.py**: Example script to conduct offline analysis of NJE packets.
* **client.py**: a dummy NJE client to connect and receive any outstanding messages or heartbeats until timeout.
* **jcl.py**: Example python script to send JCL to a target system. Take two arguments: JCL to send and a userID.
* **JCL Folder**: Example JCL files for testing:
  * id.jcl: Executes the UNIX commands 'sh id;who;uname -a' on the NEWYORK node.
  * nop.jcl: Executes the 'does nothing' program *IEFBR14* on the NEWYORK node.
  * tso.jcl: Executes the the TSO command 'TIME' on the NEWYORK node.
