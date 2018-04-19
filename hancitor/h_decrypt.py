#!/usr/bin/env python
from unicorn import *
from unicorn.x86_const import *
import re, struct, sys, base64, pefile, binascii, hashlib

__author__  = "Jeff White [karttoon] @noottrak"
__email__   = "jwhite@paloaltonetworks.com"
__version__ = "1.1.10"
__date__    = "24JAN2018"

# 1.1.10 - 006f7fd56fa89fa576fa95221bdf16422d66787ca366e57816ff6d8a957d7de5
# Adjust regex for cncs as /4/forum.php

# v1.1.9 - 6dcbf652b96a7aea16d0c2e72186173d9345f722c9592e62820bcfe477b2b297
# Added functionality to strip URL from new RTF variant of Hancitor

# v1.1.8 - 85d2ba3f12877bf7e531ec1970909f2ea20f55ba17d27f4a5b65e8e8dc493909
# Added new variant stub and ability to adjust offset for B64 decoding.

# v1.1.7 - efe7cfe0c08265e1a4eed68a1e544ba0e98fff98942e0e55941e1899aba71579
# Latest versions Base64 buffer is longer than what is decoded so caused padding issue. Adjusted to account.

# v1.1.6
# Newer versions of Unicorn Engine (1.0.0+) changed memory management so I needed to adjust some areas to re-init the memory sections each loop

# v1.1.5 - 62e6e5dc0c3927a8c5d708688ca2b56df93848b15a4c38aab173c5a8384395f9
# Added variant 4 to phase 1 decoder - now doing alternating 4-byte XOR keys
# They fixed variant 3 so it now alternates correctly. Key-pairs will need to be added manually.

# v1.1.4 - 800bf028a23440134fc834efc5c1e02cc70f05b2e800bbc285d7c92a4b126b1c
# Added variant 3 to phase 1 decoder - now doing 4-byte XOR key
# They have a bug in their code so likely V4 will be along shortly

# v1.1.3 - 5527d778becf75d8ce7f45876a88add06f79577ad7c4cbd1a8f42aa0e9991320
# Changed phase 1 variant 2 decoder to now brute force values outside of Unicorn
# Restricted it to 27K possibilities (30^3) for add, xor1, xor2

# v1.1.2 - 5a3c843bfcf31c2f2f2a2e4d5f5967800a2474e07323e8baa46ff3ac64d60d4a
# New variant of decoder in phase 1
# Different add value and alternates XOR each character with 0xF and 0x10

# v1.1.1 - 7eaa732d95252bf05440aca56f1b2e789dab39af72031a11fc597be88b1ede7f
# New variant has encrypted URLs
# First 5 bytes of a SHA1 hash of a key are used as decrypt key to RC4 encrypted data holding C2 URLs

# v1.1.0 - e1cb2bc858327f9967a3631056f7e513af17990d87780e4ee1c01bc141d3dc7f
# New stub bytes pre-header added

# v1.0.9 - fc1f1845e47d4494a02407c524eb0e94b6484045adb783e90406367ae20a83ac
# Adjusted HTTP export to account for change in URL structure, gate.php to forum.php
# Will not extract regardless of PHP file name

# v1.0.8 - b506faff00ae557056d387442e9d4d2a53e87c5f9cd59f75db9ba5525ffa0ba3
# New shellcode decoding binary with string "STARFALL"
# Will now extract regardless of magic header

# v1.0.7 - 14211739584aa0f04ba8845a9b66434529e5e4636f460d34fa84821ebfb142fd
# Hancitor directly embedded - fileless inject of PE but URLs scrapable

# v1.0.6 - 98f4e4436a7b2a0844d94526f5be5b489604d2b1f586be16ef578cc40d6a61b7
# Brute force of second stage keys (false key plants/re-positioned)
# Cleaned up handling for multiple sections
# e5b54afc85e7d282d7b2c0045e6e74967ff41ac571880929728f4d49693003a8
# Also added new first stage decoder for above hash variants
# 2ac7d8a063127641e71911941c549b8ce889c8587c1d948c72b1aca900069e5e
# New mechanisms for H1N1 decrypting added

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

# Converted unpacking to a function to make brute forcing XOR easier
def phase1_unpack(ADD_VALUE, XOR_VALUE, SIZE_VALUE, ENC_PAYLOAD):

    ADDRESS = 0x1000000
    mu = Uc(UC_ARCH_X86, UC_MODE_32)

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

def phase1_unpack_variant2(ENC_PAYLOAD):
    # Try version 2
    # 5a3c843bfcf31c2f2f2a2e4d5f5967800a2474e07323e8baa46ff3ac64d60d4a New decoding variant

    print "\t[!] Attempting variant 2..."

    # Brute force
    ADD_VALUE = 0
    SUCCESS_FLAG = 0

    while ADD_VALUE < 30:

        XOR_VALUE_1 = 0

        while XOR_VALUE_1 < 30:

            XOR_VALUE_2 = 0

            while XOR_VALUE_2 < 30:
                try:
                    B64_DATA = phase1_unpack_v2decode(ADD_VALUE, XOR_VALUE_1, XOR_VALUE_2, 322, ENC_PAYLOAD)
                    B64_DATA = re.search("[A-Za-z0-9+/=]{300,}", B64_DATA)
                    DEC_PAYLOAD = base64.b64decode(B64_DATA.group())
                except:
                    DEC_PAYLOAD = ''
                if "This program cannot be run in DOS mode" in DEC_PAYLOAD:
                    print "\t[*] Successfully brute forced Hancitor encoder variant v2"
                    print "\t[-] ADD:  %s\n\t[-] XOR1: %s\n\t[-] XOR2: %s" % (
                    hex(ADD_VALUE), hex(XOR_VALUE_1), hex(XOR_VALUE_2))

                    B64_DATA = phase1_unpack_v2decode(ADD_VALUE, XOR_VALUE_1, XOR_VALUE_2, len(ENC_PAYLOAD), ENC_PAYLOAD)
                    B64_DATA = re.search("[A-Za-z0-9+/=]{300,}", B64_DATA)
                    DEC_PAYLOAD = base64.b64decode(B64_DATA.group())

                    FILE_NAME = sys.argv[1].split(".")[0] + "_S1.exe"
                    FILE_HANDLE = open(FILE_NAME, "w")
                    FILE_HANDLE.write(DEC_PAYLOAD)
                    FILE_HANDLE.close()

                    print "\t[!] Success! Written to disk as %s" % FILE_NAME

                    SUCCESS_FLAG = 1

                XOR_VALUE_2 += 1

            XOR_VALUE_1 += 1

        ADD_VALUE += 1

    return SUCCESS_FLAG

def phase1_unpack_v2decode(ADD_VALUE, XOR_VALUE_1, XOR_VALUE_2, LENGTH_VALUE, ENC_PAYLOAD):

    # Leaving partial Unicorn data for preservation

    ## If we have shellcode, find shellcode function (this is to avoid brute forcing 16.7M possible combinations, 0xFF^3 (add/dual xor)
    ##SC = re.search("\x8B\x45\xF8\x8D\x14\x01\x8A\x02.+\x41\x88\x02\x3B\xCE\x72\xE4", SC_DATA).group(0)
    ##SC = "\x90\x89\xE8" + SC[3:]

    # Build shellcode with variables
    # sub_C52 loc_ED3
    #SC = b'\x90\x89\xE8\x8D\x14\x01\x8A\x02\x04' + chr(ADD_VALUE) + '\xF6\xC1\x01\x75\x04\x34' + chr(XOR_VALUE_1) + '\xEB\x02\x34' + chr(XOR_VALUE_2) + '\x41\x88\x02\x3B\xCE\x72\xE4'

    # Build final code to emulate
    #X86_CODE32 = SC + ENC_PAYLOAD[10:]

    # The above functions work but emulating this brute-force with Unicorn takes a SIGNFICANT amount of time (15+mins)
    # Deleted most of the Unicorn part and re-wrote for Python with partial B64 matching to reduce time to <5sec
    mu = ''
    count = 0
    for i in ENC_PAYLOAD[10:LENGTH_VALUE]:

        i = ord(i) + ADD_VALUE

        if count % 2 == 0:
            i = i ^ XOR_VALUE_1
        else:
            i = i ^ XOR_VALUE_2

        try:
            mu += chr(i)
        except:
            continue

        count += 1

    return mu

def phase1_unpack_variant3(ENC_PAYLOAD):
    # Try version 3
    # 800bf028a23440134fc834efc5c1e02cc70f05b2e800bbc285d7c92a4b126b1c New decoding variant

    print "\t[!] Attempting variant 3..."

    SUCCESS_FLAG = 0

    # Don't have the shellcode or a way to brute force the key, so will need to manually add them here for the time being
    # Insert new xor keys below -- NOTE: this variant will probably never be used again as it was a broken version of variant 4
    XOR_KEYS = [
        "\x78\x50\x34\x3F",
        "\x78\x53\x38\x35"
    ]

    for XOR_VALUE in XOR_KEYS:
        if SUCCESS_FLAG == 0:
            try:
                B64_DATA = phase1_unpack_v3decode(XOR_VALUE, 322, ENC_PAYLOAD)
                B64_DATA = re.search("[A-Za-z0-9+/=]{300,}", B64_DATA)
                DEC_PAYLOAD = base64.b64decode(B64_DATA.group())
                if "This program cannot be run in DOS mode" in DEC_PAYLOAD:
                    print "\t[*] Successfully decoded Hancitor with variant v3"
                    print "\t[-] XOR: 0x%s" % ("".join([hex(ord(i))[2:] for i in XOR_VALUE]))

                    B64_DATA = phase1_unpack_v3decode(XOR_VALUE, len(ENC_PAYLOAD), ENC_PAYLOAD)
                    B64_DATA = re.search("[A-Za-z0-9+/=]{300,}", B64_DATA)
                    DEC_PAYLOAD = base64.b64decode(B64_DATA.group())

                    FILE_NAME = sys.argv[1].split(".")[0] + "_S1.exe"
                    FILE_HANDLE = open(FILE_NAME, "w")
                    FILE_HANDLE.write(DEC_PAYLOAD)
                    FILE_HANDLE.close()

                    print "\t[!] Success! Written to disk as %s" % FILE_NAME

                    SUCCESS_FLAG = 1
            except:
                pass

    return SUCCESS_FLAG

def phase1_unpack_v3decode(XOR_VALUE_1, LENGTH_VALUE, ENC_PAYLOAD):

    mu = ''

    l = len(XOR_VALUE_1)
    for i in range(0, len(ENC_PAYLOAD[10:LENGTH_VALUE])):

        mu += chr(ord(ENC_PAYLOAD[10:LENGTH_VALUE][i]) ^ ord(XOR_VALUE_1[i % l]))

    return mu

def phase1_unpack_variant4(ENC_PAYLOAD):
    # Try version 4
    # 62e6e5dc0c3927a8c5d708688ca2b56df93848b15a4c38aab173c5a8384395f9 New decoding variant

    print "\t[!] Attempting variant 4..."

    SUCCESS_FLAG = 0

    # Don't have the shellcode or a way to brute force the key, so will need to manually add them here for the time being
    # Insert new xor-pairs below
    XOR_PAIRS = {
        "\x78\x53\x38\x35":"\xC9\xA1\x43\x24"
    }

    for XOR_PAIR in XOR_PAIRS:
        if SUCCESS_FLAG == 0:
            try:
                XOR_VALUE_1 = XOR_PAIR
                XOR_VALUE_2 = XOR_PAIRS[XOR_PAIR]
                B64_DATA = phase1_unpack_v4decode(XOR_VALUE_1, XOR_VALUE_2, 322, ENC_PAYLOAD)
                B64_DATA = re.search("[A-Za-z0-9+/=]{300,}", B64_DATA)
                DEC_PAYLOAD = base64.b64decode(B64_DATA.group())
                if "This program cannot be run in DOS mode" in DEC_PAYLOAD:
                    print "\t[*] Successfully decoded Hancitor with variant v4"
                    print "\t[-] XOR1: 0x%s" % ("".join([hex(ord(i))[2:] for i in XOR_VALUE_1]))
                    print "\t[-] XOR2: 0x%s" % ("".join([hex(ord(i))[2:] for i in XOR_VALUE_2]))

                    B64_DATA = phase1_unpack_v4decode(XOR_VALUE_1, XOR_VALUE_2, len(ENC_PAYLOAD), ENC_PAYLOAD)
                    B64_DATA = re.search("[A-Za-z0-9+/=]{300,}", B64_DATA)

                    # efe7cfe0c08265e1a4eed68a1e544ba0e98fff98942e0e55941e1899aba71579
                    # Their B64 buffers now extend beyond what they actually decode, which cause padding issue
                    B64_DATA = B64_DATA.group()
                    B64_LEN = len(B64_DATA)

                    while B64_LEN % 4 != 0:
                        B64_LEN -= 1
                    DEC_PAYLOAD = base64.b64decode(B64_DATA[0:B64_LEN])

                    FILE_NAME = sys.argv[1].split(".")[0] + "_S1.exe"
                    FILE_HANDLE = open(FILE_NAME, "w")
                    FILE_HANDLE.write(DEC_PAYLOAD)
                    FILE_HANDLE.close()

                    print "\t[!] Success! Written to disk as %s" % FILE_NAME

                    SUCCESS_FLAG = 1
            except:
                pass

    return SUCCESS_FLAG

def phase1_unpack_v4decode(XOR_VALUE_1, XOR_VALUE_2, LENGTH_VALUE, ENC_PAYLOAD):

    mu = ''
    count = 0

    # 85d2ba3f12877bf7e531ec1970909f2ea20f55ba17d27f4a5b65e8e8dc493909
    # Later variants began 2 bytes in after the usual payload start
    # This will try to determine the start position by expected B64 start
    start_value = 0
    for i in range(0,10):

        if chr(ord(ENC_PAYLOAD[10+i]) ^ ord(XOR_VALUE_1[0])) == "T":

            start_value = i

    for i in range(10 + start_value, len(ENC_PAYLOAD[10 + start_value:LENGTH_VALUE]), 4):

        if count % 2 == 0:
            l = len(XOR_VALUE_1)
            for index,value in enumerate(range(i, i+4)):
                mu += chr(ord(ENC_PAYLOAD[value]) ^ ord(XOR_VALUE_1[index]))

        else:
            l = len(XOR_VALUE_2)
            for index,value in enumerate(range(i, i+4)):
                mu += chr(ord(ENC_PAYLOAD[value]) ^ ord(XOR_VALUE_2[index]))

        count += 1

    return mu

# Samples without embedded PE Hancitor payloads are encoding URLs to download the payload
def http_decode(ENC_PAYLOAD):

    ADDRESS = 0x1000000
    mu = Uc(UC_ARCH_X86, UC_MODE_32)

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

def phase1(ADD_VALUE, SIZE_VALUE, XOR_VALUE, ENC_PAYLOAD):
    SIZE_VALUE = struct.pack("i", SIZE_VALUE)

    # Brute force XOR key as they are changing more frequently
    while ord(XOR_VALUE) < 255:

        mu = phase1_unpack(ADD_VALUE, XOR_VALUE, SIZE_VALUE, ENC_PAYLOAD)

        if "This program cannot be run in DOS mode" in mu.mem_read(0x10000F9, 150):
            print "\t\t[*] Found XOR key '%s'" % hex(ord(XOR_VALUE))
            SIZE_VALUE = struct.unpack("i", SIZE_VALUE)[0]
            break
        else:
            URLS = []
            PAYLOAD_SIZE = struct.unpack("i", SIZE_VALUE)[0]
            DEC_PAYLOAD = http_decode(str(mu.mem_read(0x10000F9, PAYLOAD_SIZE)))
            if re.search("http://.*\.exe", DEC_PAYLOAD) and XOR_VALUE != 0x01:
                print "\t\t[*] Found XOR key '%s'" % hex(ord(XOR_VALUE))
                for i in re.search("http://.*\.exe", DEC_PAYLOAD).group(0).split("\x00"):
                    URLS.append(i.replace("http", "hxxp"))
                break
            else:
                XOR_VALUE = chr(ord(XOR_VALUE) + 1)

    # Print results
    if "This program cannot be run in DOS mode" not in mu.mem_read(0x10000F9, 150) and URLS == []:

        # Try variant 2
        SUCCESS_FLAG = phase1_unpack_variant2(ENC_PAYLOAD)

        # Try variant 3
        if SUCCESS_FLAG == 0:
            SUCCESS_FLAG = phase1_unpack_variant3(ENC_PAYLOAD)

        # Try variant 4
        if SUCCESS_FLAG == 0:
            SUCCESS_FLAG = phase1_unpack_variant4(ENC_PAYLOAD)

        if SUCCESS_FLAG == 0:
            print "\t[!] Failed to decode phase 1! Shutting down"
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
            # 00a437416a2d5e23dbf671e4c1498cb0d0978ce4ee8bfbaca49413352d553a65
            # Phase 2 is Nullsoft directly
            if re.search("NullsoftInst", mu.mem_read(0x10000F9, SIZE_VALUE)):
                print "\t[!] Detected Nullsoft Installer! Shutting down"
                sys.exit(1)
            # 14211739584aa0f04ba8845a9b66434529e5e4636f460d34fa84821ebfb142fd - gate.php
            # fc1f1845e47d4494a02407c524eb0e94b6484045adb783e90406367ae20a83ac - forum.php
            # Direct embed
            if re.search("http://[a-z0-9]{5,50}\.[a-z]{2,10}/[a-zA-Z0-9]{2,10}\/[a-zA-Z0-9]+\.php", mu.mem_read(0x10000F9, SIZE_VALUE)):
                URLS = re.findall("http://[a-z0-9]{5,50}\.[a-z]{2,10}/[a-zA-Z0-9]{1,10}\/[a-zA-Z0-9]+\.php", mu.mem_read(0x10000F9, SIZE_VALUE))
                print "\t[!] Detected Hancitor URLs"
                for i in URLS:
                    print "\t[-] %s" % i.replace("http", "hxxp")
                sys.exit(1)
        else:
            print "\t[!] Hancitor not embedded, decoding download URLs"
            for i in URLS:
                print "\t[-] %s" % i.replace("http", "hxxp")
            sys.exit(1)

def phase2_xorhunt(FILE_NAME):
    # Previously seen XOR keys
    # "HEWRTWEWET"
    # "BLISODOFDO"
    try:
        pe = pefile.PE(FILE_NAME)
        for i in pe.sections:
            if ".rdata" in i.Name:
                XOR_VALUE = re.findall("\x00\x00[\x41-\x5A\x61-\x7A]{10}", i.get_data())#.group(0)[3:]
    except:
        print "\t[!] Unknown packer, unable to decode! Shutting down"
        sys.exit(1)
    return XOR_VALUE

def phase2_unpack(XOR_VALUE, FILE_CONTENT):

    ADDRESS = 0x1000000
    mu = Uc(UC_ARCH_X86, UC_MODE_32)

    # Initialize stack
    mu.mem_map(ADDRESS, 4 * 1024 * 1024)

    # loc_406442
    SC = b'\x85\xC9\x7C\x29\xBE\x40\x00\x00\x01\x90\xB8\x67\x66\x66\x66\xF7\xE9\xC1\xFA\x02\x8B\xC2\xC1\xE8\x1F\x03\xC2\x8D\x04\x80\x03\xC0\x8B\xD1\x2B\xD0\x8A\x82\x36\x00\x00\x01\x30\x04\x0E\x41\x81\xF9\x00\x50\x00\x00\x72\xCA'

    MAGIC_OFFSET = re.search(XOR_VALUE, FILE_CONTENT)

    if MAGIC_OFFSET == None:
        return
    else:
        try:
            # Identifies start of encrypted binary
            MAGIC_OFFSET = list([x.start() for x in re.finditer(XOR_VALUE, FILE_CONTENT)])[1] - 30
            MAGIC_BASE = re.search(XOR_VALUE, FILE_CONTENT).start()
            MAGIC_COUNT = 1
            # 001a4073d1cdefeb67a813207fde44c6430323eac1faf94ab05649b7e39b9f43_S1.exe
            # Some samples have the decrypt key repeated in the .rdata section
            while MAGIC_OFFSET - MAGIC_BASE < 1000:
                MAGIC_OFFSET = list([x.start() for x in re.finditer(XOR_VALUE, FILE_CONTENT)])[MAGIC_COUNT] - 30
                MAGIC_COUNT += 1
        except:
            return ""
            #print "\t[!] Encrypted payload not found! Shutting down"
            #sys.exit(1)
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

def h1n1_packed(FILE_CONTENT):
    NULL_OFFSET = list([x.start() for x in re.finditer("\x00\x00..", FILE_CONTENT)])
    for i in NULL_OFFSET:
        XOR_VALUE = 0
        TEST_SECTION = FILE_CONTENT[i:i + 4]
        while XOR_VALUE < 254:
            M_VAL = ord(TEST_SECTION[2]) ^ XOR_VALUE
            Z_VAL = ord(TEST_SECTION[3]) ^ (XOR_VALUE + 1)
            if M_VAL == 77 and Z_VAL == 90:
                print "\t[-] Found start of rotating XOR %s" % (hex(XOR_VALUE))
                MAGIC_OFFSET = i + 2
                SAVE_XOR = XOR_VALUE
                break
            XOR_VALUE += 1
    XOR_VALUE = SAVE_XOR
    SIZE_VALUE = len(FILE_CONTENT[MAGIC_OFFSET:])
    ENC_PAYLOAD = FILE_CONTENT[MAGIC_OFFSET:MAGIC_OFFSET + SIZE_VALUE]
    DEC_PAYLOAD = ""
    for i in ENC_PAYLOAD:
        DEC_PAYLOAD += chr(ord(i) ^ XOR_VALUE)
        if XOR_VALUE < 255:
            XOR_VALUE += 1
        else:
            XOR_VALUE = 0
    return DEC_PAYLOAD

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
    t = re.findall(r'(33c0(.{10}ab|.{6}ab)+)', binascii.hexlify(data))

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

        # Uncomment for other strings (anti-VM/commands/etc)
        #print mu.mem_read(STACK + 4096, 100)
        if "gate.php" in mu.mem_read(STACK + 4096, 100):
            URLS.append(str(mu.mem_read(STACK + 4096, 100)))
        mu.mem_write(STACK, '\x00' * (4096 * 2))

    return URLS

def main():

    ###############
    # First Phase #
    ###############

    print "[+] FILE: %s\n\t#### PHASE 1 ####" % sys.argv[1]

    # Open document and copy data
    FILE_HANDLE = open(sys.argv[1], "r")
    FILE_CONTENT = ""
    for i in FILE_HANDLE:
        FILE_CONTENT += i
    FILE_HANDLE.close()

    # Pull out base64 encoded shellcode
    # Adjusted to try and account for catastrophic backtracking
    SC_DATA = re.search("\00[A-Za-z0-9+/]{3000,}[=]{1,2}\00", FILE_CONTENT)
    if SC_DATA != None:
        SC_DATA = SC_DATA.group()
        SC_DATA = base64.b64decode(SC_DATA)

    # Extract data depending on version of dropper variables
    if SC_DATA != None:
        print "\t[-] Found B64 shellcode"
        # Pull from shellcode
        INIT_VALUES = re.search("\x8A\x04\x0F\x04.\x34.\x88\x04\x0F\x41\x81\xF9....", SC_DATA).group(0)
        ADD_VALUE = INIT_VALUES[4]
        XOR_VALUE = INIT_VALUES[6]
        SIZE_VALUE = INIT_VALUES[13:]
        # Extract payload base on shellcode data
        MAGIC_OFFSET = re.search("\x50\x4F\x4C\x41", FILE_CONTENT)
        MAGIC_OFFSET = MAGIC_OFFSET.start()
        SIZE_VALUE = struct.unpack("<L", SIZE_VALUE)[0]
        ENC_PAYLOAD = FILE_CONTENT[MAGIC_OFFSET:MAGIC_OFFSET + SIZE_VALUE]
    else:
        print "\t[!] No raw B64 shellcode, going blind"
        # Extract payload from magic header bytes
        if re.search("\x49\x45\x4E\x44\xAE\x42\x60\x82[\x00-\xFF]{4,8}\x08\x00[\x00-\xFF]+\x00{128}", FILE_CONTENT):
            print "\t\t[*] Found magic header v1 '%s'" % (re.search(
                "\x49\x45\x4E\x44\xAE\x42\x60\x82[\x00-\xFF]{4,8}\x08\x00", FILE_CONTENT).group(0))[8:-2]
            ENC_PAYLOAD = (re.search("\x49\x45\x4E\x44\xAE\x42\x60\x82[\x00-\xFF]{4,8}\x08\x00[\x00-\xFF]+\x00{128}",
                                     FILE_CONTENT).group(0))[8:]
            SIZE_VALUE = len(ENC_PAYLOAD) - 128
        # New magic header
        # e1cb2bc858327f9967a3631056f7e513af17990d87780e4ee1c01bc141d3dc7f
        elif re.search("\x08\x01\x01\x01\x06.\x00\x7F\xFF\xD9[\x00-\xFF]{4,8}\x08\x00[\x00-\xFF]+\x00{128}",
                       FILE_CONTENT):
            print "\t\t[*] Found magic header v2 \"%s\"" % (re.search(
                "\x01\x01\x06.\x00\x7F\xFF\xD9[\x00-\xFF]{4,8}\x08\x00", FILE_CONTENT).group(0))[8:-2]
            ENC_PAYLOAD = (re.search("\x01\x01\x06.\x00\x7F\xFF\xD9[\x00-\xFF]{4,8}\x08\x00[\x00-\xFF]+\x00{128}",
                                     FILE_CONTENT).group(0))[8:]
            SIZE_VALUE = len(ENC_PAYLOAD) - 128
        # New magic header
        # 85d2ba3f12877bf7e531ec1970909f2ea20f55ba17d27f4a5b65e8e8dc493909
        elif re.search("\x10\x04\x01\x00\x40.\x04\x07\xFF\xD9[\x00-\xFF]{4,8}\x08\x00[\x00-\xFF]+\x00{128}",
                       FILE_CONTENT):
            print "\t\t[*] Found magic header v3 \"%s\"" % (re.search(
                "\x01\x00\x40.\x04\x07\xFF\xD9[\x00-\xFF]{4,8}\x08\x00", FILE_CONTENT).group(0))[8:-2]
            ENC_PAYLOAD = (re.search(
                "\x10\x04\x01\x00\x40.\x04\x07\xFF\xD9[\x00-\xFF]{4,8}\x08\x00[\x00-\xFF]+\x00{128}",
                FILE_CONTENT).group(0))[8:]
            SIZE_VALUE = len(ENC_PAYLOAD) - 128
        else:
            XOR_VALUE = 0
            print "\t[!] Magic header not found!"
            try:
                ENC_PAYLOAD = list([x.start() for x in re.finditer("\xFF{400}", FILE_CONTENT)])[-1]
                while XOR_VALUE < 16:
                    DEC_PAYLOAD = ""
                    # We don't know end of binary so we scrape all and regex B64 out
                    for i in FILE_CONTENT[ENC_PAYLOAD:]:
                        if (ord(i) + 3) ^ 12 < 255:
                            DEC_PAYLOAD += chr((ord(i) + 3) ^ XOR_VALUE)
                    B64_PE = re.search("[A-Za-z0-9+/]{3000,}[=]{1,2}", DEC_PAYLOAD)
                    if B64_PE != None:
                        try:
                            B64_PE = B64_PE.group()
                            B64_PE = base64.b64decode(B64_PE)
                            if "This program cannot be run in DOS mode" in B64_PE:
                                print "\t[-] Attempting to find encoded binary"
                                print "\t\t[*] Found XOR key '%s' " % hex(XOR_VALUE)
                                break
                        except:
                            continue
                    XOR_VALUE += 1
                if XOR_VALUE == 16:
                    sys.exit(1)
            except:
                # Quick check for RTF and URLs
                # 6dcbf652b96a7aea16d0c2e72186173d9345f722c9592e62820bcfe477b2b297
                if re.search("objdata", FILE_CONTENT, re.IGNORECASE) and re.search("objclass", FILE_CONTENT,
                                                                                   re.IGNORECASE) and re.search(
                    "objupdate", FILE_CONTENT, re.IGNORECASE):

                    print "\t[!] Found RTF Variant"

                    URLS = []
                    B64_PE = None

                    for HEX_STRING in re.findall("[a-fA-F0-9]{2000,}", FILE_CONTENT):

                        HEX_STRING = HEX_STRING.decode("hex")

                        # Check for URLs first - variant 1
                        for url in re.findall("\'http.+?\'", HEX_STRING):
                            if url[1:-1] not in URLS:
                                URLS.append(url[1:-1])

                        # Check for B64 encoded PE - variant 2
                        if "TVqQAAM" in HEX_STRING:
                            B64_PE = base64.b64decode(re.search("TVqQA[A-Za-z0-9+/=]{1000,}", HEX_STRING).group())

                    if URLS != []:
                        print "\t[!] Extracted URLs"
                        for url in URLS:
                            print "\t[-] %s" % url.replace("http", "hxxp")
                        sys.exit(1)

                # Failure to detect ANY method for decoding
                if B64_PE == None:
                    print "\t[!] Unable to process %s" % sys.argv[1]
                    sys.exit(1)

        # Phase1 most common variables
        ADD_VALUE = "\x03"
        XOR_VALUE = "\x00"  # Seen \x13 and \x10

    # Check to see if we detected the B64 embedded payload (not shellcode), otherwise proceed with decoding regularly
    try:
        FILE_NAME = sys.argv[1].split(".")[0] + "_S1.exe"
        FILE_HANDLE = open(FILE_NAME, "w")
        FILE_HANDLE.write(B64_PE)
        FILE_HANDLE.close()
        print "\t[!] Success! Written to disk as %s" % FILE_NAME
    except:
        phase1(ADD_VALUE, SIZE_VALUE, XOR_VALUE, ENC_PAYLOAD)

    ################
    # Second Phase #
    ################

    # Open file just written and copy data
    FILE_HANDLE = open(FILE_NAME, "r")
    FILE_CONTENT = ""
    for i in FILE_HANDLE:
        FILE_CONTENT += i
    FILE_HANDLE.close()

    print "\t#### PHASE 2 ####"

    # 7eaa732d95252bf05440aca56f1b2e789dab39af72031a11fc597be88b1ede7f
    # Started to RC4 encrypt C2 URLs
    if re.search("api.ipify.org", FILE_CONTENT) and re.search("CryptDecrypt", FILE_CONTENT) and re.search("CryptDeriveKey", FILE_CONTENT):

        print "\t[!] Detected RC4 encrypted version C2"

        pe = pefile.PE(FILE_NAME)
        for i in pe.sections:
            if ".data" in i.Name:

                DATA_SECTION = i.get_data()

                # Decrypt key is first 5 bytes of a SHA1 hash of the first 8 bytes preceeding RC4 encrypted data
                RC4_KEY = hashlib.sha1(DATA_SECTION[16:24]).digest()[:5]
                print "\t\t[*] RC4 decrypt key (hex) '0x%s'" % RC4_KEY.encode('hex')
                ENCRYPT_DATA = DATA_SECTION[24:]

                # RC4 decrypt routine
                KEY_ARRAY = range(256)
                INDEX_MOD = 0
                DECRYPT_DATA = []

                # KSA
                for INDEX_VAL in range(256):

                    INDEX_MOD = (INDEX_MOD + KEY_ARRAY[INDEX_VAL] + ord(RC4_KEY[INDEX_VAL % len(RC4_KEY)])) % 256
                    KEY_ARRAY[INDEX_VAL], KEY_ARRAY[INDEX_MOD] = KEY_ARRAY[INDEX_MOD], KEY_ARRAY[INDEX_VAL]

                # PRGA
                INDEX_VAL = 0
                INDEX_MOD = 0

                for value in ENCRYPT_DATA:

                    INDEX_VAL = (INDEX_VAL + 1) % 256
                    INDEX_MOD = (INDEX_MOD + KEY_ARRAY[INDEX_VAL]) % 256
                    KEY_ARRAY[INDEX_VAL], KEY_ARRAY[INDEX_MOD] = KEY_ARRAY[INDEX_MOD], KEY_ARRAY[INDEX_VAL]
                    DECRYPT_BYTE = ord(value) ^ KEY_ARRAY[(KEY_ARRAY[INDEX_VAL] + KEY_ARRAY[INDEX_MOD]) % 256]

                    DECRYPT_DATA.append(chr(DECRYPT_BYTE))

                DECRYPT_DATA = ''.join(DECRYPT_DATA)

                if re.findall("http://[a-z0-9]{5,50}\.[a-z]{1,10}/[a-zA-Z0-9]{1,10}\/[a-zA-Z0-9]+\.php", DECRYPT_DATA):
                    if re.search("^[0-9]+\x00\x00\x00\x00", DECRYPT_DATA):
                        BUILD_NUMBER = re.search("^[0-9]+\x00\x00\x00\x00", DECRYPT_DATA).group(0)[:-4]
                        print "\t[-] Hancitor Build Number '%s'" % BUILD_NUMBER
                    URLS = re.findall("http://[a-z0-9]{5,50}\.[a-z]{1,10}/[a-zA-Z0-9]{1,10}\/[a-zA-Z0-9]+\.php", DECRYPT_DATA)
                    print "\t[!] Detected Hancitor URLs"
                    for i in URLS:
                        print "\t[-] %s" % i.replace("http", "hxxp")
                    sys.exit(1)
                else:
                    print "\t[!] Failed to decrypt phase 2! Shutting down"
                    sys.exit(1)
    else:
        # Find XOR keys
        XOR_VALUE = phase2_xorhunt(FILE_NAME)

    # Decode payload
    DEC_PAYLOAD = ""
    for key in XOR_VALUE:
        key = key[2:] # Strip two leading nulls from regex
        DEC_PAYLOAD = phase2_unpack(key, FILE_CONTENT)
        if "This program cannot be run in DOS mode" in DEC_PAYLOAD or "NullsoftInst" in DEC_PAYLOAD:
            XOR_VALUE = key
            print "\t[-] XOR: %s" % XOR_VALUE
            break

    # Print results
    if "This program cannot be run in DOS mode" not in DEC_PAYLOAD:
        if re.search("NullsoftInst", DEC_PAYLOAD):
            print "\t[!] Detected Nullsoft Installer! Shutting down"
        else:
            print "\t[!] Failed to decode phase 2! Shutting down"
        sys.exit(1)
    else:
        # Write file to disk
        FILE_NAME = sys.argv[1].split(".")[0] + "_S2.exe"
        FILE_HANDLE = open(FILE_NAME, "w")
        FILE_HANDLE.write(DEC_PAYLOAD)
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
        print "\t[!] No Hancitor URLs found"
    else:
        print "\t[-] Hancitor URLs"
        for i in FIND_URL:
            print "\t[-] %s" % i.replace("http", "hxxp")
        sys.exit(1)

    DEC_PAYLOAD = h1n1_packed(FILE_CONTENT)

    # Print results
    if "Upack" not in DEC_PAYLOAD:
        print "\t[!] Failed to decode phase 3! Shutting down"
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

if __name__ == '__main__':
    main()
