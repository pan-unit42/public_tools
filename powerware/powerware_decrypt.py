'''
	Decrypter script for PowerWare variant that purports to be the Locky malware
	family. Requires the pycrypto library. 

	Written by Josh Grunzweig
'''

from binascii import unhexlify
import sys, os, fnmatch

try:
	from Crypto.Cipher import AES
except:
	print("pycrypto library not found. Please install this library before proceeding.")
	print("pycrypto may be easily installed on Windows using the following command:")
	print("easy_install http://www.voidspace.org.uk/python/pycrypto-2.6.1/pycrypto-2.6.1.win32-py2.7.exe")
	print("Reference: http://stackoverflow.com/questions/11405549/how-do-i-install-pycrypto-on-windows")
	sys.exit(1)

def decrypt_data(data):
	key = unhexlify("05D5C0B29EFD643501880100B0D9A9998025040FA4D67B62EC167436E8C33E81")
	iv = unhexlify("AC78AEFC1789057469D166A3FADEB71C")
	mode = AES.MODE_CBC
	e = AES.new(key, mode, iv)
	return e.decrypt(data)

DRIVE = 'C:\\'
OVERWRITE = False

print "[+] Note that this script should be run with administrator privileges."
print "[+] Recursively searching through the {} drive.".format(DRIVE)


for root, dirnames, filenames in os.walk(DRIVE):
	for filename in fnmatch.filter(filenames, '*.locky'):
		path = os.path.join(root, filename)
		print "[+] Found .locky file: {}".format(path)
		npath = '.'.join(path.split(".")[0:-1])
		if os.path.isfile(npath) and OVERWRITE == False:
			print "[*] Possible original file ({}) found. Change the 'OVERWRITE' variable in the script to overwrite this file."
		else:
			orig_fh = open(path, 'rb')
			orig_data = orig_fh.read()
			orig_fh.close()

			fh = open(npath, 'wb')
			fh.write(decrypt_data(orig_data[0:2048]) + orig_data[2048:])
			fh.close()
			print "[+] Decrypted file written to {}".format(npath)
