import pefile
import sys
import os
from itertools import cycle, izip

'''
This script will take a RTF document, containing the recently reported CMSTAR
malware family, as an argument. It will parse through the file looking for a MZ
header that is encrypted with a 4-byte XOR key. If found, it will write this
payload to 'dropped.dll'.

Author: Josh Grunzweig
'''

def xor(message, key):
	return ''.join(chr(ord(c)^ord(k)) for c,k in izip(message, cycle(key)))


filename = sys.argv[1]
s = open(filename, "rb")
r = s.read()

k1 = '\xbe\xba\xfe\xca'

output_filename = "dropped.dll.raw"

for c in [0, 1, 2, 3]:
	rdata = xor(r[c:], k1)
	if "MZ\x90" in rdata:
		rindex = rdata.index("MZ\x90")
		print "[+] Found MZ Header at offset 0x{:02X}".format(rindex)
		o = open(output_filename, 'wb')
		o.write(rdata[rindex:])
		o.close()

if os.path.isfile(output_filename):
	pe = pefile.PE(output_filename)
	offset = pe.get_overlay_data_start_offset()
	if offset:
		print "[+] MZ Overlay found at offset: {} | 0x{:02X}".format(offset, offset)	
		o = open(output_filename, 'rb').read()
		nfilename = output_filename[:-4]
		o2 = open(nfilename, 'wb')
		o2.write(o[:offset])
		print "[+] Wrote {}".format(nfilename)
