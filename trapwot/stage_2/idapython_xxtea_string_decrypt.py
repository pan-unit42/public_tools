'''

This script uses the position of the cursor within IDA Pro in order to
decrypt any strings encrypted with XXTEA. The script will add a comment at
the cursor position in the event decryption is successful.

Unfortunately, XXTEA decryption occurs in a number of different ways within
the disassembled malware, which prevents me from doing this in a more
automated fashion.

Example:

	** Cursor on encrypted string start position **

	Python>d()
	[+] Data to decrypt: '(\xee\xfe\x0c\x82\x1f,\xe58\tK\xde@!_\x98\x9c\x02\n9]\xd7*\xf9\xfc\x9d4h\xe7:r\xa3\xf6\x9bm\xca\x11\xddg\x17\xefc\xe7\x1e\xd7\x06\xab\x194\xa1~\x8f'
	[+] Decrypted: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00\x00\x00.\x00\x00\x00'

Author = Josh Grunzweig [Unit42]
Copyright = 'Copyright 2014, Palo Alto Networks'

'''

import struct
import types
from binascii import *

def raw_xxtea(v, n, k):
	assert type(v) == type([])
	assert type(k) == type([]) or type(k) == type(())
	assert type(n) == type(1)

	def MX():
		return ((z>>5)^(y<<2)) + ((y>>3)^(z<<4))^(sum^y) + (k[(p & 3)^e]^z)

	def u32(x):
		return x & 0xffffffff

	y = v[0]
	sum = 0
	DELTA = 0x9e3779b9
	if n > 1:	   # Encoding
		z = v[n-1]
		q = 6 + 52 / n
		while q > 0:
			q -= 1
			sum = u32(sum + DELTA)
			e = u32(sum >> 2) & 3
			p = 0
			while p < n - 1:
				y = v[p+1]
				z = v[p] = u32(v[p] + MX())
				p += 1
			y = v[0]
			z = v[n-1] = u32(v[n-1] + MX())
		return 0
	elif n < -1:	# Decoding
		n = -n
		q = 6 + 52 / n
		sum = u32(q * DELTA)
		while sum != 0:
			e = u32(sum >> 2) & 3
			p = n - 1
			while p > 0:
				z = v[p-1]
				y = v[p] = u32(v[p] - MX())
				p -= 1
			z = v[n-1]
			y = v[0] = u32(v[0] - MX())
			sum = u32(sum - DELTA)
		return 0
	return 1


class XXTEAException(Exception):
	pass


class XXTEA:
	"""
	XXTEA wrapper class, easy to use and compatible (by duck typing) with the
	Blowfish class.
	"""

	def __init__(self, key):
		"""
		Initializes the inner class data with the given key. The key must be
		128-bit (16 characters) in length.
		"""
		if len(key) != 16 or type(key) != type(""):
			raise XXTEAException("Invalid key")
		self.key = struct.unpack("IIII", key)
		assert len(self.key) == 4
		self.initCTR()

	def encrypt(self, data):
		"""
		Encrypts a block of data (of size a multiple of 4 bytes, minimum 8
		bytes) and returns the encrypted data.
		"""
		if len(data) % 4 != 0:
			raise XXTEAException("Invalid data - size must be a multiple of 4 bytes")
		ldata = len(data) / 4
		idata = list(struct.unpack("%dI" % ldata, data))
		if raw_xxtea(idata, ldata, self.key) != 0:
			raise XXTEAException("Cannot encrypt")
		return struct.pack("%dI" % ldata, *idata)

	def decrypt(self, data):
		"""
		Decrypts a block of data encrypted with encrypt() and returns the
		decrypted data.
		"""
		if len(data) % 4 != 0:
			raise XXTEAException("Invalid data - size must be a multiple of 4 bytes")
		ldata = len(data) / 4
		idata = list(struct.unpack("%dI" % ldata, data))
		if raw_xxtea(idata, -ldata, self.key) != 0:
			raise XXTEAException("Cannot encrypt")
		return struct.pack("%dI" % ldata, *idata)

	def initCTR(self, iv=0):
		"""
		Initializes CTR mode with optional 32-bit IV.
		"""
		self.ctr_iv = [0, iv]
		self._calcCTRBUF()

	def _calcCTRBUF(self):
		"""
		Calculates one (64-bit) block of CTR keystream.
		"""
		self.ctr_cks = self.encrypt(struct.pack("II", *self.ctr_iv)) # keystream block
		self.ctr_iv[1] += 1
		if self.ctr_iv[1] > 0xffffffff:
			self.ctr_iv[0] += 1
			self.ctr_iv[1] = 0
		self.ctr_pos = 0

	def _nextCTRByte(self):
		"""Returns one byte of CTR keystream"""
		b = ord(self.ctr_cks[self.ctr_pos])
		self.ctr_pos += 1
		if self.ctr_pos >= len(self.ctr_cks):
			self._calcCTRBUF()
		return b

	def encryptCTR(self, data):
		"""
		Encrypts a buffer of data with CTR mode. Multiple successive buffers
		(belonging to the same logical stream of buffers) can be encrypted
		with this method one after the other without any intermediate work.
		"""
		if type(data) != types.StringType:
			raise RuntimeException, "Can only work on 8-bit strings"
		result = []
		for ch in data:
			result.append(chr(ord(ch) ^ self._nextCTRByte()))
		return "".join(result)

	def decryptCTR(self, data):
		return self.encryptCTR(data)

	def block_size(self):
		return 8

	def key_length(self):
		return 16

	def key_bits(self):
		return self.key_length()*8


def d():
	ea = here()
	n_ea = ea
	data = ""
	while True:
		if Byte(n_ea) == 0 and Byte(n_ea+1) == 0:
			break
		data += chr(Byte(n_ea))
		n_ea += 1

	print "[+] Data to decrypt:", repr(data)
	key = 'a\xc3^\xa9\xe2\x8fN\xd4\xd4\xdbm\x1b\x9a>\x93\x08'
	x = XXTEA(key)
	decrypted_string = x.decrypt(data)
	print "[+] Decrypted:", repr(decrypted_string)
	MakeComm(ea, decrypted_string)
