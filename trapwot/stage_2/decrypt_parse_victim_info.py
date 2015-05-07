'''

Script to decrypt and parse victim information sent by Trapwot stage 2
downloader.

Example:

	stage_2 jgrunzweig$ hexdump -C victim_information.bin
	00000000  b0 a1 a5 a5 95 a5 a5 b7  a1 a5 a3 a4 14 b8 b6 a7  |................|
	00000010  a5 ac a1 b3 81 a5 e6 9f  f9 f0 d6 c0 d7 d6 f9 e4  |................|
	00000020  c1 c8 cc cb cc d6 d1 d7  c4 d1 ca d7 f9 c8 c9 d2  |................|
	00000030  d7 fa d6 c8 d5 c9 8b c0  dd c0 b1 ad a5 cc c0 dd  |................|
	00000040  d5 c9 ca d7 c0                                    |.....|
	00000045

	stage_2 jgrunzweig$ python decrypt_parse_victim_info.py victim_information.bin
	Identifier : Process Integrity Level
	Size       : 4
	Data       : '0x12288'

	Identifier : OS Version
	Size       : 4
	Data       : '6.1.177.29'

	Identifier : Language
	Size       : 2
	Data       : '0x1033'

	Identifier : Install Path
	Size       : 36
	Data       : 'C:\\Users\\Administrator\\mlwr_smpl.exe'

	Identifier : Default Web Browser
	Size       : 8
	Data       : 'iexplore'


Author = Josh Grunzweig [Unit42]
Copyright = 'Copyright 2014, Palo Alto Networks'

'''

import sys
from struct import *
from itertools import cycle, izip

def xor(message, key):
	return ''.join(chr(ord(c)^ord(k)) for c,k in izip(message, cycle(key)))

ENUMS = {'18' : 'OS Version',
         '19' : 'Language',
         '20' : 'Default Web Browser',
         '21' : 'Process Integrity Level',
         '22' : 'Install Path'
        }

def parse_victim_info(data):
	pos = 0
	while pos < len(data):
		identifier = str(unpack("B", data[pos])[0])
		pos += 1
		size = unpack("H", data[pos:(pos+2)])[0]
		pos += 2
		d = unpack(str(size)+"s", data[pos:(pos+size)])[0]
		if int(identifier) == 21:
			d = "0x" + str(unpack("I", d)[0])
		elif int(identifier) == 19:
			d = "0x" + str(unpack("H", d)[0])
		elif int(identifier) == 18:
			d = "%d.%d.%d.%d" % unpack("BBBB", d)
		pos += size
		if identifier in ENUMS:
			identifier = ENUMS[identifier]
		print "Identifier : %s" % identifier
		print "Size       : %d" % size
		print "Data       :", repr(d)
		print

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print "Usage: python %s [file]" % __file__
		sys.exit(1)

	f = sys.argv[1]
	fh = open(f, 'rb')
	fd = fh.read()
	fh.close()

	decrypted_fd = xor(fd, "\xA5")
	parse_victim_info(decrypted_fd)
