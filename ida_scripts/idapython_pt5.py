import sys
sys.path.append('/usr/local/lib/python2.7/site-packages')
import pefile

def extract_exe(name, begin, size):
	buff = ""
	for c in range(0, size):
		buff += chr(Byte(begin+c))
	f = open(name, 'wb')
	f.write(buff)
	f.close()

def calculate_exe_size(begin):
	buff = ""
	for c in range(0, 1024):
		buff += chr(Byte(begin+c))
	pe = pefile.PE(data=buff)
	total_size = 0
	# Add total size of headers
	total_size += pe.OPTIONAL_HEADER.SizeOfHeaders
	# Iterate through each section and add section size
	for section in pe.sections:
		total_size += section.SizeOfRawData
	return total_size

def find_string_occurrences(string):
	results = []
	base = idaapi.get_imagebase() + 1024
	while True:
		ea = FindBinary(base, SEARCH_NEXT|SEARCH_DOWN|SEARCH_CASE, '"%s"' % string)
		if ea != 0xFFFFFFFF:
			base = ea+1
		else:
			break 
		results.append(ea)
	return results

def find_embedded_exes():
	results = []
	exes = find_string_occurrences("!This program cannot be run in DOS mode.")
	if len(exes) > 1:
		for exe in exes:
			m = Byte(exe-77)
			z = Byte(exe-76)
			if m == ord("M") and z == ord("Z"):
				mz_start = exe-77
				print "[*] Identified embedded executable at the following offset: 0x%x" % mz_start
				results.append(mz_start)
	return results

embedded_exes = find_embedded_exes()
if embedded_exes:
	for exe in embedded_exes:
		total_size = calculate_exe_size(exe)
		filename = "dropped_0x%x" % exe
		extract_exe(filename, exe, total_size)
		cwd = os.getcwd()
		print "[*] Wrote %s/%s" % (cwd, filename)