import sys
from binascii import *
from struct import *

'''
This script takes a raw payload that is downloaded by CMSTAR and decodes it to
the actual PE32 file. The format of the file downloaded is such that the first
four bytes are expected to be 0xFFFFFFFF. The following 3 DWORDs are used by
the decoding routine to de-obfuscate the remaining data.

Author: Josh Grunzweig
'''

file = sys.argv[1]

fh = open(file, 'rb')
fdata = fh.read()
fh.close()

if fdata[0:4] == "\xFF\xFF\xFF\xFF":
	print "So far, so good."

v1 = unpack("<I", fdata[4:8])[0]
v2 = unpack("<I", fdata[8:12])[0]
v3 = unpack("<I", fdata[12:16])[0]

print "V1: {}".format(v1)
print "V2: {}".format(v2)
print "V3: {}".format(v3)

remaining_fdata = fdata[16:]

output_buffer_len = len(remaining_fdata) >> 2 # Dividing by 4.

def decodeCycle(dword, rounds, modvalue):
	output = 1
	for c in range(rounds):
		output = (output * dword) % modvalue
	return output

resulting_buffer = ""
for counter in range(output_buffer_len):
	dwordraw = remaining_fdata[(counter*4):(counter*4+4)]
	dword = unpack("<I", dwordraw)[0]
	resulting_buffer += chr(decodeCycle(dword, v2, v3))

fh = open(file+".exe", 'wb')
fh.write(resulting_buffer)
fh.close()