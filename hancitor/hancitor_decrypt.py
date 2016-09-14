#!/usr/bin/env python
from unicorn import *
from unicorn.x86_const import *
import re, struct, sys, base64, pefile, binascii

__author__  = "Jeff White [karttoon] @noottrak"
__email__   = "jwhite@paloaltonetworks.com"
__version__ = "1.0.5"
__date__    = "13SEP2016"

# v1.0.5 - 6dbb31e435e2ff2b7f2b185dc19e6fb63da9ab3553d20b868a298b4c100aeb2a
# New Hancitor second stage XOR key
# Change phase 2 to automatically extract XOR key and extract encrypted binary

# v1.0.4 - 8f26a30a1fc71b7e9eb12e3b94317b7dd5827e2cbcfb3cd3feb684af6a73b4e6
# Hancitor no longer embedded, instead encoded URls that will download it

# v1.0.3 - b586c11f5485e3a38a156cba10379a4135a8fe34aa2798af8d543c059f0ac9a4
# Utilized code from Mak and Sysopfb to unpack Upack H1N1 DLL and extract C2

# v1.0.2 - b586c11f5485e3a38a156cba10379a4135a8fe34aa2798af8d543c059f0ac9a4
# Added XOR brute for phase 1
# Added including stripped MZ header on phase 1 EXE
# Added check for H1N1 phase 2 payload

# v1.0.1 - f648b0d91956f79a2645cbdf0c1612801107d783a6c6bb0ea41582b9b2161199
# Malware now XORs in macro to obfuscate B64 shellcode
# Added ability to extract phase 1 based off regex, assumes stored values in shellcode

# v1.0.0 - 03aef51be133425a0e5978ab2529890854ecf1b98a7cf8289c142a62de7acd1a
# Initial release, dumps phase 1 and phase 2 packed payloads
# Prints Hancitor C2 URLs

# Setup Unicorn enviroment
ADDRESS = 0x1000000
mu = Uc(UC_ARCH_X86, UC_MODE_32)

###############
# First Phase #
###############

print "[+] FILE: %s\n\t#### PHASE 1 ####" % sys.argv[1]

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

# Extract data depending on version of dropper variables
if SC_DATA != None:
    print "\t[-] Found B64 shellcode"
    # Pull from shellcode
    ADD_VALUE  = SC_DATA[2966]
    XOR_VALUE  = SC_DATA[2968]
    SIZE_VALUE = SC_DATA[2975:2979]
    # Extract payload base on shellcode data
    MAGIC_OFFSET = re.search("\x50\x4F\x4C\x41", FILE_CONTENT)
    MAGIC_OFFSET = MAGIC_OFFSET.start()
    SIZE_VALUE = struct.unpack("<L", SIZE_VALUE)[0]
    ENC_PAYLOAD = FILE_CONTENT[MAGIC_OFFSET:MAGIC_OFFSET + SIZE_VALUE]
else:
    print "\t[!] No raw B64 shellcode, going blind"
    # Extract payload blind without shellcode
    MAGIC_OFFSET = re.findall("\x50\x4F\x4C\x41.*\x00{128}", FILE_CONTENT)
    SIZE_VALUE = len(MAGIC_OFFSET[0]) - 128
    ENC_PAYLOAD = MAGIC_OFFSET[0][0:SIZE_VALUE]
    # Phase1 most common variables
    ADD_VALUE  = "\x03"
    XOR_VALUE  = "\x00" # Seen \x13 and \x10

SIZE_VALUE = struct.pack("i", SIZE_VALUE)

# Converted unpacking to a function to make brute forcing XOR easier
def phase1_unpack(ADD_VALUE, XOR_VALUE, SIZE_VALUE):

    # Initialize stack
    mu.mem_map(ADDRESS, 4 * 1024 * 1024)

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

    return mu

# Samples without embedded PE Hancitor payloads are encoding URLs to download the payload
def http_decode(ENC_PAYLOAD):

    # Initialize stack
    mu.mem_map(ADDRESS, 4 * 1024 * 1024)

    # Build shellcode
    # sub_11B0
    SC = b'\x6B\xC0\x06\x99\x83\xE2\x07\x03\xC2\xC1\xF8\x03\xC3'
    # sub_1193
    SC += b'\x6B\xC0\x06\x25\x07\x00\x00\x80\x79\x05\x48\x83\xC8\xF8\x40\xC3'
    # sub_11A0
    SC += b'\x8D\x48\xBF\x80\xF9\x19\x77\x07\x0F\xBE\xC0\x83\xE8\x41\xC3\x8D\x48\x9F\x80\xF9\x19\x77\x07\x0F\xBE\xC0\x83\xE8\x47\xC3\x8D\x48\xD0\x80\xF9\x09\x77\x07\x0F\xBE\xC0\x83\xC0\x04\xC3\x3C\x2B\x75\x04\x6A\x3E\x58\xC3\x3C\x2F\x75\x04\x6A\x3F\x58\xC3\x33\xC0\xC3'
    # sub_11F0
    SC += b'\x55\x8B\xEC\x51\x51\x8B\x45\x08\x83\x65\xFC\x00\x89\x45\xF8\x8A\x00\x84\xC0\x74\x68\x53\x56\x57\xE8\xA3\xFF\xFF\xFF\x8B\xD8\x8B\x45\xFC\xE8\x7C\xFF\xFF\xFF\x8B\x4D\xF8\x8D\x14\x08\x8B\x45\xFC\xE8\x7B\xFF\xFF\xFF\x8B\xF8\x8B\xF0\xF7\xDE\x8D\x4E\x08\xB0\x01\xD2\xE0\xFE\xC8\xF6\xD0\x20\x02\x83\xFF\x03\x7D\x09\x8D\x4E\x02\xD2\xE3\x08\x1A\xEB\x15\x8D\x4F\xFE\x8B\xC3\xD3\xF8\x8D\x4E\x0A\xD2\xE3\x08\x02\xC6\x42\x01\x00\x08\x5A\x01\xFF\x45\x08\x8B\x45\x08\x8A\x00\xFF\x45\xFC\x84\xC0\x75\x9E\x5F\x5E\x5B\xC9\xC3'

    X86_CODE32 = SC + ENC_PAYLOAD

    # Write code to memory
    mu.mem_write(ADDRESS, X86_CODE32)
    # Start of encoded data
    mu.reg_write(UC_X86_REG_EAX, 0x1000000 + len(SC))
    # Initialize Stack for functions
    mu.reg_write(UC_X86_REG_ESP, 0x1300000)
    mu.mem_write(0x1300004, b'\x10\x00\x00\xDE')

    # Print 150 characters of encrypted value
    #print "Encrypt: %s" % mu.mem_read(0x1000000 + len(SC),150)

    # Run the code
    try:
        mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32))
    except UcError as e:
        pass

    # Print 150 characters of decrypted value
    #print "Decrypt: %s" % mu.mem_read(0x1000000 + len(SC),150)

    # Return length of decoded payload, parsing will take place later
    return mu.mem_read(0x1000000 + len(SC), len(ENC_PAYLOAD))

# Brute force XOR key as they are changing more frequently
while ord(XOR_VALUE) < 255:
    mu = phase1_unpack(ADD_VALUE, XOR_VALUE, SIZE_VALUE)
    if "This program cannot be run in DOS mode" in mu.mem_read(0x10000F9, 150):
        print "\t\t[*] Found XOR key %s" % hex(ord(XOR_VALUE))
        SIZE_VALUE = struct.unpack("i", SIZE_VALUE)[0]
        break
    else:
        URLS = []
        PAYLOAD_SIZE = struct.unpack("i", SIZE_VALUE)[0]
        DEC_PAYLOAD = http_decode(str(mu.mem_read(0x10000F9, PAYLOAD_SIZE)))
        if "http://" in DEC_PAYLOAD:
            for i in str(DEC_PAYLOAD).split("\x00"):
                if "http://" in i:
                    URLS.append(i.replace("http", "hxxp"))
            break
        else:
            XOR_VALUE = chr(ord(XOR_VALUE) + 1)

# Print results
if "This program cannot be run in DOS mode" not in mu.mem_read(0x10000F9, 150) and URLS == []:
    print "\t[!] Failed to decoded phase 1! Shutting down."
    sys.exit(1)
else:
    if "This program cannot be run in DOS mode" in mu.mem_read(0x10000F9, 150):
        print "\t[-] ADD:  %s\n\t[-] XOR:  %s\n\t[-] SIZE: %s" % (hex(ord(ADD_VALUE)), hex(ord(XOR_VALUE)), SIZE_VALUE)
        # Write file to disk
        FILE_NAME = sys.argv[1].split(".")[0] + "_S1.exe"
        FILE_HANDLE = open(FILE_NAME, "w")
        # New anti-analysis added to strip MZ header so we add it back in
        if mu.mem_read(0x10000F9 + 0x0C, 2) != "\x4D\x5A":
            print "\t\t[*] Detected stripped MZ header, adding back in"
            FILE_HANDLE.write(b"\x4D\x5A\x90" + mu.mem_read(0x10000F9 + 0x0C, SIZE_VALUE))
        else:
            FILE_HANDLE.write(mu.mem_read(0x10000F9 + 0x0C, SIZE_VALUE))
        FILE_HANDLE.close()
        print "\t[!] Success! Written to disk as %s" % FILE_NAME
    else:
        print "\t[!] Hancitor not embedded, decoding download URLs"
        for i in URLS:
            print "\t[-] %s" % i
        sys.exit(1)

################
# Second Phase #
################

# Open file just written and copy data
FILE_HANDLE = open(FILE_NAME, "r")
FILE_CONTENT = ""
for i in FILE_HANDLE:
    FILE_CONTENT += i
FILE_HANDLE.close()

def phase2_xorhunt(FILE_NAME):
    # Previously seen XOR keys
    # "HEWRTWEWET"
    # "BLISODOFDO"
    pe = pefile.PE(FILE_NAME)
    for i in pe.sections:
        if ".rdata" in i.Name:
            XOR_VALUE = re.search("\x00\x00\x00\x00[\x01-\xFF]{10}", i.get_data()).group(0)[4:]
    return XOR_VALUE

def phase2_unpack(XOR_VALUE):

    # Initialize stack
    mu.mem_map(ADDRESS, 4 * 1024 * 1024)

    # loc_406442
    SC = b'\x85\xC9\x7C\x29\xBE\x40\x00\x00\x01\x90\xB8\x67\x66\x66\x66\xF7\xE9\xC1\xFA\x02\x8B\xC2\xC1\xE8\x1F\x03\xC2\x8D\x04\x80\x03\xC0\x8B\xD1\x2B\xD0\x8A\x82\x36\x00\x00\x01\x30\x04\x0E\x41\x81\xF9\x00\x50\x00\x00\x72\xCA'

    MAGIC_OFFSET = re.search(XOR_VALUE, FILE_CONTENT)
    if MAGIC_OFFSET == None:
        return
    else:
        # Identifies start of encrypted binary
        MAGIC_OFFSET = list([x.start() for x in re.finditer(XOR_VALUE, FILE_CONTENT)])[1] - 30
    ENC_PAYLOAD = FILE_CONTENT[MAGIC_OFFSET:MAGIC_OFFSET + 20480]

    # Build final code to emulate
    X86_CODE32 = SC + XOR_VALUE + ENC_PAYLOAD

    # Write code to memory
    mu.mem_write(ADDRESS, X86_CODE32)
    # Start of encoded data
    mu.reg_write(UC_X86_REG_EDX, 0x1000040)
    # Initialize ECX counter to 0
    mu.reg_write(UC_X86_REG_ECX, 0x0)
    # Initialize Stack for functions
    mu.reg_write(UC_X86_REG_ESP, 0x1300000)

    # Print 150 characters of encrypted value
    #print "Encrypt: %s" % mu.mem_read(0x1000040,150)

    # Run the code
    try:
        mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32))
    except UcError as e:
        pass

    # Print 150 characters of decrypted value
    #print "Decrypt: %s" % mu.mem_read(0x1000040,150)

    return mu.mem_read(0x1000040, 0x5000)

print "\t#### PHASE 2 ####"

# Find XOR key
XOR_VALUE = phase2_xorhunt(FILE_NAME)

# Decode payload
DEC_PAYLOAD = phase2_unpack(XOR_VALUE)

# Print results
if "This program cannot be run in DOS mode" not in DEC_PAYLOAD:
    if re.search("NullsoftInst", DEC_PAYLOAD):
        print "\t[!] Detected Nullsoft Installer! Shutting down."
    else:
        print "\t[!] Failed to decode phase 2! Shutting down."
    sys.exit(1)
else:
    print "\t[-] XOR: % s" % (XOR_VALUE)
    # Write file to disk
    FILE_NAME = sys.argv[1].split(".")[0] + "_S2.exe"
    FILE_HANDLE = open(FILE_NAME, "w")
    FILE_HANDLE.write(mu.mem_read(0x1000040, 0x5000))
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

# Find URLs in Hancitor
FIND_URL = re.findall("http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", FILE_CONTENT)

# Print results
print "\t### PHASE 3 ###"
if FIND_URL == []:
    if __name__ == '__main__':
        print "\t[!] No Hancitor URLs found"
        # Search for "HEWRTWEWET", which is used subsequent H1N1 packed file (using ZwUnmapViewOfSection injection into explorer.exe)
        if re.search(b"\x48\x45\x57\x52\x54\x57\x45\x57\x45\x54", FILE_CONTENT):
            if re.search(b"\x6A\x40\x6A\x00\x6A\x01\x50\x6A\x00\x6A\x00\x6A\x00\x51\x6A\xFF\xFF\x75\xEC", FILE_CONTENT):
                print "\t\t[*] Detected H1N1 payload (ZwUnmapViewOfSection injection)"
        else:
            sys.exit(1)
else:
    print "\t[-] Hancitor URLs"
    for i in FIND_URL:
        print "\t[-] %s" % i.replace("http", "hxxp")
    sys.exit(1)

def h1n1_packed(FILE_CONTENT):
    MAGIC_OFFSET = re.findall("\x32\x00\x00\x7E\x31\x00\x00[\x00-\xFF]*\x00{128}", FILE_CONTENT)
    SIZE_VALUE = len(MAGIC_OFFSET[0]) - 64
    ENC_PAYLOAD = MAGIC_OFFSET[0][7:SIZE_VALUE]
    XOR_VALUE = ord(ENC_PAYLOAD[0]) ^ 77 # "M"
    print "\t[-] Found start of rotating XOR %s" % (hex(XOR_VALUE))
    DEC_PAYLOAD = ""
    for i in ENC_PAYLOAD:
        DEC_PAYLOAD += chr(ord(i) ^ XOR_VALUE)
        if XOR_VALUE < 255:
            XOR_VALUE += 1
        else:
            XOR_VALUE = 0
    return DEC_PAYLOAD

DEC_PAYLOAD = h1n1_packed(FILE_CONTENT)

# Print results
if "Upack" not in DEC_PAYLOAD:
    print "\t[!] Failed to decode phase 3! Shutting down."
    sys.exit(1)
else:
    print "\t[-] Detected H1N1 DLL packed with Upack"
    # Write file to disk
    FILE_NAME = sys.argv[1].split(".")[0] + "_S3.dll"
    FILE_HANDLE = open(FILE_NAME, "w")
    FILE_HANDLE.write(DEC_PAYLOAD)
    FILE_HANDLE.close()
    print "\t[!] Success! Written to disk as %s" % FILE_NAME

################
# Fourth Phase #
################

# Open file just written and copy data
FILE_HANDLE = open(FILE_NAME, "r")
FILE_CONTENT = ""
for i in FILE_HANDLE:
    FILE_CONTENT += i
FILE_HANDLE.close()

def h1n1_dll_unpack(FILE_NAME):
    ##############################################################
    # Code copied from Mak                                       #
    # https://codegists.com/snippet/python/h1n1_emupy_mak_python #
    ##############################################################
    pe = pefile.PE(FILE_NAME)
    for s in pe.sections:
        if s.Name.strip("\x00") == '.rsrc':
            code_section = s
        if s.Name.strip("\x00") == '.Upack':
            data_section = s
    base = pe.OPTIONAL_HEADER.ImageBase
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint + base
    STACK = 0x90000

    mu = Uc(UC_ARCH_X86, UC_MODE_32)

    ## map binary
    mu.mem_map(base, 0x1000)
    mu.mem_map(base + code_section.VirtualAddress, code_section.Misc_VirtualSize)
    mu.mem_map(base + data_section.VirtualAddress, data_section.Misc_VirtualSize)

    # map stack - two pages
    mu.mem_map(STACK, 4096 * 2)
    mu.mem_write(base, pe.get_data()[:pe.OPTIONAL_HEADER.SizeOfHeaders])
    mu.mem_write(base + code_section.VirtualAddress, code_section.get_data())

    mu.reg_write(UC_X86_REG_ESP, STACK + 4096)

    try:
        mu.emu_start(ep, 16)
    except UcError as e:
        pass

    data = mu.mem_read(base + data_section.VirtualAddress, data_section.Misc_VirtualSize)
    data_section.SizeOfRawData = len(data)
    data_section.PointerToRawData = code_section.PointerToRawData
    data_section.Name = ".code".ljust(8, "\x00")
    pe.set_bytes_at_rva(data_section.VirtualAddress, str(data))
    code_section.PointerToRawData = 0
    code_section.SizeOfRawData = 0
    return pe

def h1n1_scrape(FILE_NAME):
    #######################################################################
    # Code copied from Sysopfb                                            #
    # https://github.com/sysopfb/Malware_Scripts/blob/master/h1n1/h1n1.py #
    #######################################################################
    STACK = 0x90000
    code_base = 0x10000000
    mu = Uc(UC_ARCH_X86, UC_MODE_32)

    data = open(FILE_NAME, 'rb').read()
    t = re.findall(r'(33c0(.{10}ab)+)', binascii.hexlify(data))

    mu.mem_map(code_base, 0x1000)

    mu.mem_map(STACK, 4096 * 2)

    URLS = []

    for i in range(len(t)):
        mu.mem_write(code_base, '\x00' * 0x1000)
        mu.mem_write(STACK, '\x00' * (4096 * 2))
        mu.mem_write(code_base, binascii.unhexlify(t[i][0]))
        mu.reg_write(UC_X86_REG_ESP, STACK + 4096)
        mu.reg_write(UC_X86_REG_EDI, STACK + 4096)
        try:
            mu.emu_start(code_base, code_base + len(binascii.unhexlify(t[i][0])))
        except:
            pass

        if "gate.php" in mu.mem_read(STACK + 4096, 100):
            URLS.append(str(mu.mem_read(STACK + 4096, 100)))
        mu.mem_write(STACK, '\x00' * (4096 * 2))

    return URLS

print "\t##### PHASE 4 #####"
print "\t[-] Unpacking Upack H1N1 DLL"
pe = h1n1_dll_unpack(FILE_NAME)
FILE_NAME = FILE_NAME.split("_")[0] + "_S3_unpack.dll"
pe.write(FILE_NAME)
print "\t[!] Success! Written to disk as %s" % FILE_NAME

URLS = h1n1_scrape(FILE_NAME)

# Print results
print "\t[-] H1N1 URLs"
for i in URLS[0].split("|"):
    try:
        URL = i.split(":")[0]
        URI = i.split(":")[1].strip("80")
        print "\t[-] hxxp://%s%s" % (URL, URI)
    except:
        pass


