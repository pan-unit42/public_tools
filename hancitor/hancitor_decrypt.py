#!/usr/bin/env python
from unicorn import *
from unicorn.x86_const import *
import re, struct, sys, base64

__author__  = "Jeff White [karttoon] @noottrak"
__email__   = "jwhite@paloaltonetworks.com"
__version__ = "1.0.0"
__date__    = "24AUG2016"

###############################
# THIS IS NOW DEPRECATED      #
# ORIGINAL PRESERVED FOR BLOG #
# PLEASE USE h_decrypt.py     #
###############################

# Setup Unicorn enviroment
ADDRESS = 0x1000000
mu = Uc(UC_ARCH_X86, UC_MODE_32)
mu.mem_map(ADDRESS, 4 * 1024 * 1024)

###############
# First Phase #
###############

# Open Word Document and copy data
FILE_HANDLE = open(sys.argv[1], "r")
FILE_CONTENT = ""
for i in FILE_HANDLE:
    FILE_CONTENT += i
FILE_HANDLE.close()

# Pull out base64 encoded shellcode
try:
    SC_DATA = re.search("[A-Za-z0-9+/]{1024,}.*([A-Za-z0-9+/]{128,}==|[A-Za-z0-9+/]{128,}=)", FILE_CONTENT)
    if SC_DATA != None:
        SC_DATA = SC_DATA.group()
        SC_DATA = base64.b64decode(SC_DATA)
except:
    print "[!] Unable to process %s" % sys.argv[1]
    sys.exit(1)

# Locate variables
ADD_VALUE  = SC_DATA[2966]
XOR_VALUE  = SC_DATA[2968]
SIZE_VALUE = SC_DATA[2975:2979]

# Build shellcode with variables
# sub_8A6
SC = b'\x8A\x04\x0F\x04' + ADD_VALUE + b'\x34' + XOR_VALUE + b'\x88\x04\x0F\x41\x81\xF9' + SIZE_VALUE + b'\x72\xED\x57\xE8\x61\x00\x00\x00\x83\x7D\xFC\x01'
# sub_7CA
SC += b'\x6B\xC0\x06\x99\x83\xE2\x07\x03\xC2\xC1\xF8\x03\xC3'
# sub_7D7
SC += b'\x6B\xC0\x06\x25\x07\x00\x00\x80\x79\x05\x48\x83\xC8\xF8\x40\xC3'
# sub_7E7
SC += b'\x8D\x48\xBF\x80\xF9\x19\x77\x07\x0F\xBE\xC0\x83\xE8\x41\xC3\x8D\x48\x9F\x80\xF9\x19\x77\x07\x0F\xBE\xC0\x83\xE8\x47\xC3\x8D\x48\xD0\x80\xF9\x09\x77\x07\x0F\xBE\xC0\x83\xC0\x04\xC3\x3C\x2B\x75\x04\x6A\x3E\x58\xC3\x3C\x2F\x75\x04\x6A\x3F\x58\xC3\x33\xC0\xC3'
# sub_827
SC += b'\x55\x8B\xEC\x51\x51\x8B\x45\x08\x83\x65\xFC\x00\x89\x45\xF8\x8A\x00\x84\xC0\x74\x68\x53\x56\x57\xE8\xA3\xFF\xFF\xFF\x8B\xD8\x8B\x45\xFC\xE8\x7C\xFF\xFF\xFF\x8B\x4D\xF8\x8D\x14\x08\x8B\x45\xFC\xE8\x7B\xFF\xFF\xFF\x8B\xF8\x8B\xF0\xF7\xDE\x8D\x4E\x08\xB0\x01\xD2\xE0\xFE\xC8\xF6\xD0\x20\x02\x83\xFF\x03\x7D\x09\x8D\x4E\x02\xD2\xE3\x08\x1A\xEB\x15\x8D\x4F\xFE\x8B\xC3\xD3\xF8\x8D\x4E\x0A\xD2\xE3\x08\x02\xC6\x42\x01\x00\x08\x5A\x01\xFF\x45\x08\x8B\x45\x08\x8A\x00\xFF\x45\xFC\x84\xC0\x75\x9E\x5F\x5E\x5B\xC9\xC3'

# Extract payload
MAGIC_OFFSET = re.search("\x50\x4F\x4C\x41", FILE_CONTENT)
MAGIC_OFFSET = MAGIC_OFFSET.start()
SIZE_VALUE = struct.unpack("<L", SIZE_VALUE)[0]
ENC_PAYLOAD = FILE_CONTENT[MAGIC_OFFSET:MAGIC_OFFSET + SIZE_VALUE]

# Build final code to emulate
X86_CODE32 = SC + ENC_PAYLOAD

# Write code to memory
mu.mem_write(ADDRESS, X86_CODE32)
# Start of encoded data + offset to binary
mu.reg_write(UC_X86_REG_EDI, 0x10000F9 + 0x0C)
# Initialize ECX counter to 0
mu.reg_write(UC_X86_REG_ECX, 0x0)
# Initialize Stack for functions
mu.reg_write(UC_X86_REG_ESP, 0x1300000)

# Print 150 characters of encrypted value
#print "Encrypt: %s" % mu.mem_read(0x10000F9,150)

# Run the code
try:
    mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32))
except UcError as e:
    pass

# Print 150 characters of decrypted value
#print "Decrypt: %s" % mu.mem_read(0x10000F9,150)

# Print results
print "[+] FILE: %s\n\t#### PHASE 1 ####\n\t[-] ADD:  %s\n\t[-] XOR:  %s\n\t[-] SIZE: %s" % (sys.argv[1], hex(ord(ADD_VALUE)), hex(ord(XOR_VALUE)), SIZE_VALUE)
if mu.mem_read(0x10000F9 + 0x0C, 2) != b"\x4D\x5A":
    print "\t[!] Failed to decoded phase 1! Shutting down."
    sys.exit(1)
else:
    # Write file to disk
    FILE_NAME = sys.argv[1].split(".")[0] + "_S1.exe"
    FILE_HANDLE = open(FILE_NAME, "w")
    FILE_HANDLE.write(mu.mem_read(0x10000F9 + 0x0C, SIZE_VALUE))
    FILE_HANDLE.close()
    print "\t[!] Success! Written to disk as %s" % FILE_NAME

################
# Second Phase #
################

# Open file just written and copy data
FILE_HANDLE = open(FILE_NAME, "r")
FILE_CONTENT = ""
for i in FILE_HANDLE:
    FILE_CONTENT += i
FILE_HANDLE.close()

# Locate variables
XOR_VALUE = FILE_CONTENT[26172:26184]
#XOR_VALUE = b"\x48\x45\x57\x52\x54\x57\x45\x57\x45\x54\x48\x47"

# loc_406442
SC = b'\x85\xC9\x7C\x29\xBE\x42\x00\x00\x01\x90\xB8\x67\x66\x66\x66\xF7\xE9\xC1\xFA\x02\x8B\xC2\xC1\xE8\x1F\x03\xC2\x8D\x04\x80\x03\xC0\x8B\xD1\x2B\xD0\x8A\x82\x36\x00\x00\x01\x30\x04\x0E\x41\x81\xF9\x00\x50\x00\x00\x72\xCA'

# Extract payload
ENC_PAYLOAD = FILE_CONTENT[36880:]

# Build final code to emulate
X86_CODE32 = SC + XOR_VALUE + ENC_PAYLOAD

# Write code to memory
mu.mem_write(ADDRESS, X86_CODE32)
# Start of encoded data
mu.reg_write(UC_X86_REG_EDX, 0x1000042)
# Initialize ECX counter to 0
mu.reg_write(UC_X86_REG_ECX, 0x0)
# Initialize Stack for functions
mu.reg_write(UC_X86_REG_ESP, 0x1300000)

# Print 150 characters of encrypted value
#print "Encrypt: %s" % mu.mem_read(0x1000042,150)

# Run the code
try:
    mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32))
except UcError as e:
    pass

# Print 150 characters of decrypted value
#print "Decrypt: %s" % mu.mem_read(0x1000042,150)

# Print results
print "\t#### PHASE 2 ####\n\t[-] XOR:  %s" % (XOR_VALUE)
if mu.mem_read(0x1000042, 2) != b"\x4D\x5A":
    if re.search("NullsoftInst", FILE_CONTENT):
        print "\t[!] Detected Nullsoft Installer! Shutting down."
    else:
        print "\t[!] Failed to decode phase 2! Shutting down."
    sys.exit(1)
else:
    # Write file to disk
    FILE_NAME = sys.argv[1].split(".")[0] + "_S2.exe"
    FILE_HANDLE = open(FILE_NAME, "w")
    FILE_HANDLE.write(mu.mem_read(0x1000042, 0x5000))
    FILE_HANDLE.close()
    print "\t[!] Success! Written to disk as %s" % FILE_NAME

###############
# Third Phase #
###############

# Open file just written and copy data
FILE_HANDLE = open(FILE_NAME, "r")
FILE_CONTENT = ""
for i in FILE_HANDLE:
    FILE_CONTENT += i
FILE_HANDLE.close()

# Find URLs
FIND_URL = re.findall("http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", FILE_CONTENT)

# Print results
print "\t### PHASE 3 ###"
for i in FIND_URL:
    print "\t[-] %s" % i

