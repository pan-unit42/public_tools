import sys
import re

'''
This script is designed to be run against CMSTAR.A, CMSTAR.B, or CMSTAR.C. It 
will statically search for obfuscated strings. In the event a possible C2, 
URI, or mutex is discovered, it will output this data to STDOUT.

Author: Josh Grunzweig
''' 

def decode1(data):
	out = ""
	c = 0
	for d in data:
		out += chr(ord(d) - c - 10)
		c += 1
	return out

def decode2(data):
	out = ""
	c = 0
	for d in data:
		out += chr(ord(d) - c - 3)
		c += 1
	return out

def decode3(data):
	out = ""
	c = 0
	for d in data:
		out += chr(ord(d) - c - 8)
		c += 1
	return out

o = open(sys.argv[1], 'rb')
data = o.read()
o.close()

split_data = list(set(data.split("\x00")))

for s in split_data:
	if len(s) > 2:
		if s[0] == "{" and s[-1] == "}":
			print "[*] Possible mutex: {}".format(s)

		try:
			dec3 = decode1(s)
			if re.search("^\d+\.\d+\.\d+\.\d+$", dec3):
				print "[+] (10) URL: {}".format(dec3)
			elif re.search("\S+\.dat", dec3):
				print "[+] URI: {}".format(dec3)
		except Exception as e:
			None

		try:
			dec2 = decode2(s)
			if re.search("^http\:\/\/\w+\..+", dec2):
				print "[+] (8) URL: {}".format(dec2)
			elif re.search("\/\S+\.dat", dec2):
				print "[+] URI: {}".format(dec2)
		except Exception as e:
			None

		try:
			dec = decode3(s)
			if re.search("^http\:\/\/\w+\..+", dec):
				print "[+] (3) URL: {}".format(dec)
			elif re.search("\/\S+\.dat", dec):
				print "[+] URI: {}".format(dec)
		except Exception as e:
			None


