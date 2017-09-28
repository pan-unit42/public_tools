import subprocess
import sys
import re
import binascii

'''
This script will take a DOC document, containing the recently reported CMSTAR
malware family, as an argument. It makes use of the external 'olevba' script
to extract the embedded macro. This macro is parsed and the embedded file is
written to 'dropped.dll'.

Author: Josh Grunzweig
'''

def decrypt_xor(data, key, key_offset):
	output = ""
	seed = ord(key)
	for d in data:
		ord_d = ord(d)
		if ord_d != 0 and ord_d != seed:
			nvalue = ord_d ^ seed
			seed = (seed + key_offset) % 0x100
			output += chr(nvalue)
		else:
			output += d
	return output 


input_file = sys.argv[1]

try:
	output = subprocess.check_output(["olevba", input_file])
except subprocess.CalledProcessError as e:
	print e.message
	sys.exit(0)

if " - File format not supported" in output:
	print "[+] File format not supported. Exiting."
	sys.exit(0)
else:
	o = open("macro.vba",'wb')
	o.write(output)
	o.close()
	print "[+] Wrote macro file to macro.vba"

	o = open("macro.vba",'rb')
	macro_data = o.read()
	o.close()

	r = re.search("ReleaseLen\s+\=\s+(\d+)", macro_data)
	if r:
		print "[+] Offset found"
		r2 = re.search("Seed\s+\=\s+\&H(\w\w)", macro_data)
		if r2:
			print "[+] Key found"
			r3 = re.search("Seed\s+\=\s+Seed\s+\+\s+\&H(\w\w)", macro_data)
			if r3:
				print "[+] Key offset found"
				offset = int(r.group(1))
				key = binascii.unhexlify(r2.group(1))
				key_offset = ord(binascii.unhexlify(r3.group(1)))
				print repr(offset), repr(key), repr(key_offset)
				infile = open(input_file, 'rb')
				file_data = infile.read()
				file_data = file_data[len(file_data)-offset:]
				infile.close()
				decrypted_data = decrypt_xor(file_data, key, key_offset)
				f = open("dropped.dll",'wb')
				f.write(decrypted_data)
				f.close()
				print "[+] Wrote dropped.dll"
