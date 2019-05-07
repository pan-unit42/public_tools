# Author: Josh Grunzweig, Unit 42
# Description: Attempts to extract macros and decode embedded strings. These
# macros make use of a UAC bypass technique. Script relies on the accompanying
# olevba.py script included. 
# Reference: https://github.com/pan-unit42/public_tools/blob/master/macro_loader/macro_decode.py

import sys, re
from olevba import VBA_Parser, filter_vba


def get_macros(path):
	try:
		vba = VBA_Parser(path)
	except Exception as e:
		print("[-] Error parsing VBA")
		print(e.message)
		return
	if vba.detect_vba_macros():
		c = 1
		for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
			vba_code = filter_vba(vba_code)
			if vba_code.strip() != '':
				parse_macro(vba_code)
				fh = open("{}.vba".format(str(c)), 'wb')
				fh.write(vba_code)
				fh.close()
				c += 1


def decode(blacklist, string):
	out = ""
	for c in string:
		if c not in blacklist:
			out += c
	return out


def get_blacklist(macro_data):
	blacklist = None
	r = re.search("\"(\w+)\"\s+Like\s+", macro_data, flags=re.IGNORECASE)
	if r:
		print("[+] Found blacklist using Like method.")
		blacklist = r.group(1)
	else:
		print("[-] Blacklist not found via Like method. Checking for InStrRev().")
		r = re.search("\w+\s*\=\s*InStrRev\(\s*\"([^\"]+)\"", macro_data, flags=re.IGNORECASE)
		if r:
			blacklist = r.group(1)
		else:
			print("[-] Variable not found via InStrRev method (1).")
			r = re.search("\w+\s*\=\s*InStrRev\(\s*(\S+)\s*,", macro_data, flags=re.IGNORECASE)
			if r:			
				print("[+] Variable found via InStrRev method (2).")
				var_search = "{}\s*\=\s*\"([^\"]+)\"".format(r.group(1))
				r2 = re.search(var_search, macro_data, flags=re.IGNORECASE)
				if r2:
					print("[+] Blacklist found via InStrRev method (2).")
					blacklist = r2.group(1)
				else:
					print("[-] Blacklist not found via InStrRev method (2).")
			else:
				print("[-] Variable not found via InStrRev method (2).")
	return blacklist

		
def parse_macro(macro_data):
	blacklist = get_blacklist(macro_data)
	if blacklist:	
		print("[+] Blacklist string: {}".format(blacklist))
		all_strings = re.findall("\"([^\"\n]+)\"", macro_data)
		relevant_strings = []
		for string in all_strings:
			all_bl_chars = []
			for c in string:
				if c in blacklist:
					all_bl_chars.append(c)
			if (float(len(all_bl_chars)) / len(string)) > 0.50:
				if string != blacklist:
					relevant_strings.append(string)
		c = 1
		for string in relevant_strings:
			print("[+] Segment #{}".format(c))
			c+=1
			print(decode(blacklist, string))


get_macros(sys.argv[1])