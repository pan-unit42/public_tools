#!/usr/bin/env python3
import sys
import binascii
import pathlib
import re
try:
    #These modules might not be installed
    import iced_x86, pefile, lznt1
except:
    print("Eror importing a required module. Check to ensure you have iced_x86, pefile and lznt1 modules installed. pip install -r requirements.txt")
    sys.exit("[-] Missing required modules")
import argparse
import struct
from itertools import cycle
from pathlib import Path #use this to work with Windows and *.NIX. You're welcome

"""
This script can be used to decrypt/decompress PlugX files. It was tested on the following hashes:
3D9D004E82553F0596764F858345DCC7D2BAEE875FD644FA573A37E0904BDE88
E4C94CC2E53BEB61184F587936EE8134E3ED81872D6EE763CAC20557A5F1077C
59BA902871E98934C054649CA582E2A01707998ACC78B2570FEF43DBD10F7B6F
B5C0DB62184325FFBE2B8EF7E6F13F5D5926DEAC331EF6D542C5FA50144E0280
E2D21B5E34189FA1ACA39A13A405C792B19B6EDF020907FB9840AF1AAFBAA2F4
E2D21B5E34189FA1ACA39A13A405C792B19B6EDF020907FB9840AF1AAFBAA2F4
67E626B7304A0B14E84EC587622EE07DC0D6ECAC5A2FD08E8A2B4EDD432D2EBC

Input Parameter: Name of PlugX file to decrypt and decompress. The file extension is not important, but typically PlugX loaders have a .DAT file extension
Ouput: If sample contains hardcoded C2 info data is extracted and saved to a file.
Decompressed module (DLL) should be an PE EXE (DLL) that is loaded in-memory.

Known Issues:
Currently only tested against x86 PlugX files.  X64 will probably fail to parse correctly.

To Do:
    Search for x64 variants and modify code
    Review config file destination ports
"""

__version__ = ("1.3.0","UNIT 42 Dev: Mike Harbison","Build date 17 June, 2021")

#Using NASM
formatter = iced_x86.Formatter(iced_x86.FormatterSyntax.NASM)

#Basic x86 MZ and PE HEADER which are stripped from Plugx. This could be wrong, but seems to work. PE is a DLL as in-memory files are DLL's.
MZ_HEADER = binascii.unhexlify(
            "4D5A90000300000004000000FFFF0000"\
            "B8000000000000004000000000000000"\
            "00000000000000000000000000000000"\
            "000000000000000000000000")

PE_HEADER = binascii.unhexlify(
            "0E1FBA0E00B409CD21B8014CCD215468"\
            "69732070726F6772616D2063616E6E6F"\
            "742062652072756E20696E20444F5320"\
            "6D6F64652E0D0D0A2400000000000000"\
            "3F5713DA7B367D897B367D897B367D89"\
            "19296E8979367D89142977897F367D89"\
            "1429798978367D897B367C8961367D89"\
            "4D1076897A367D89841679897A367D89"\
            "526963687B367D890000000000000000"\
            "00000000000000000000000000000000"\
            "5045"
            )

def CheckHeader(inFile):
    """
    IN:  Data to search
    Out: Bool and file offset where NULL was found

    Description:
    This function attempts to determine if the PlugX input file is XOR encoded. XOR encoded files typically have the key in the 1st 10 bytes followed by a NULL
    If we don't have a NULL after 40 bytes, we bail and assume it's not XOR encoded or unknown.
    Returns the position found
    """
    for pos in range(40):
        if inFile[pos] == 0x00:
            #See if the XOR key repeats in the file. A typical key is 10 bytes in length (up until the NULL byte)
            KeyCheck = inFile[pos:].find(inFile[pos:])
            if KeyCheck == -1: #Key was not found 
                return False,0
            return True,pos
    return False,0

def Decrypt_XOR(EncryptData,pos):
    """
    IN: Encrypted Data and pos is the length of the XOR key. The POS value was obtained via the CheckHeader function and determines the length of the XOR key
    Out: Decrypted data from POS on. Skip NULL value

    Description:
    This function performs a rolling XOR against the input data with the key being X number of bytes of the input data 
    """
    Decrypt = bytearray()
    XOR_Key = bytearray()
    #Build XOR key
    XOR_Key = EncryptData[0:pos]
    ZipIter = zip(EncryptData[pos+1:],cycle(XOR_Key)) #Start encryptiong from where the key was found skipping NULL value
    for x,y in ZipIter:
        Decrypt.append( x^y ) #XOR 

    return Decrypt

def ReadInputFile(inFile):
    """
    IN: File to read. File is opened in binary mode
    OUT: Data or if error return False

    Description:
    Simple function that reads a file and returns its data. No checks are done on filesize or type of file provided.
    """
    try:
        with open(inFile,"rb") as fp:
            data = fp.read()
    except (IOError,ValueError):
        print(f"[-] file {inFile} not found. Please check the file and try again.")
        return False

    return data

def CheckEmbeddedC2(PlugxData):
    """
    IN: PlugX data to search.
    OUT: Bool True or False

    Description:
    Decrypts checks if input file has hardcoded C2 information. Typically PlugX has string THOR or PLUG if information is embedded. Input files that are NOT XOR encrypted
    """
    Has_config_THOR = PlugxData.find(b"ROHT") #THOR
    if Has_config_THOR == -1:
        Has_config_PLUG = PlugxData.find(b"GULP")  #PLUG 
    if Has_config_THOR!=-1 or Has_config_PLUG!=-1:
        return True
    return False

def DecryptAlgo(EncryptData,PayloadSize,StartKey,Keys):
    """
    IN: Encrypted Data, PayloadSize,StartKey and Dictionary of keys
    OUT: Bytearray of decrypted data

    Description:
    This function is the PlugX crypto routine used in compressed PlugX samples
    """
    key0=StartKey&0xFFFFFFFF
    key1=StartKey&0xFFFFFFFF
    key2=StartKey&0xFFFFFFFF
    key3=StartKey&0xFFFFFFFF
    decrypt=bytearray()
    count = 0
    while count < PayloadSize:
        key0 = ((key0 + (key0 >> 3)&0xFFFFFFFF)-Keys[0][0])&0xFFFFFFFF
        if Keys[1][1]=="-":
            key1 = ((key1 + (key1 >> 5)&0xFFFFFFFF)-Keys[1][0])&0xFFFFFFFF
        else:
            key1 = ((key1 + (key1 >> 5)&0xFFFFFFFF)+Keys[1][0])&0xFFFFFFFF
        key2 = ((key2 - (key2 << 7)&0xFFFFFFFF)+Keys[2][0])&0xFFFFFFFF
        if Keys[3][1]=="-":
            key3 = ((key3 - (key3 << 9)&0xFFFFFFFF)-Keys[3][0])&0xFFFFFFFF
        else:
             key3 = ((key3 - (key3 << 9)&0xFFFFFFFF)+Keys[3][0])&0xFFFFFFFF
        Final_Key = ((( key2&0xFF) + (key3&0xFF) + (key1&0xFF) + (key0&0xFF))&0xFF)
        decrypt.append(EncryptData[count] ^ Final_Key)
        count+=1
    return decrypt

def DumpEmbeddedConfig(PlugxData, Keys):
    """
    IN: Encrypted Data and dictionary of keys
    OUT: Bytearray of decrypted configuration data 

    Description:
    This function decrypts a PlugX embedded configuration file and saves it as filename _config.dat. This file should contain the C2 information

    """
    #Enumerate the data from the start and locate where the NULL is. Most of the data at the start is garbage 
    for x in range(len(PlugxData)):
        if PlugxData[x]==0x00:
            print(f"[+] Found NULL in header data at file offset {x}")
            break
    cSize=binascii.unhexlify("E80C1500") #size is pushed on and typically 00 15 0C
    cFound = PlugxData[x:].find(cSize)
    if cFound:
        ConfigSize_Start = cFound + x + 1
        Config_Size = struct.unpack("<i",PlugxData[ConfigSize_Start:ConfigSize_Start+4])
        Config_Start = ConfigSize_Start + 4
        Start_Key = struct.unpack("<i",PlugxData[Config_Start:Config_Start+4])
        print ("[+] Found start decryption key of 0x:{:08x}".format(Start_Key[0]))
        Decrypt_Config = DecryptAlgo(PlugxData[Config_Start:],Config_Size[0],Start_Key[0],Keys)
    else:
        Decrypt_Config=""

    return Decrypt_Config 

def DecryptModule(PlugxData, Keys):
    """
    IN: Encrypted Data and dictionary of keys
    OUT: Bytearray of decrypted module or None

    Description:
    This function decrypts a PlugX input file into the in-memory DLL

    CryptAlgoPattern_bytes are the following assembly. Used to locate encrypted payload
    push edx
    not ah
    not ah
    pop edx
    or dh, dh
    push
    """
    CryptAlgoPattern_bytes = binascii.unhexlify("52F6D4F6D45A0AF668")
    Payload_Start = PlugxData.find(CryptAlgoPattern_bytes)
    if Payload_Start == -1:
        print("[-] Did not locate crypto magic bytes in input file. Possibly x64 variant or unknown")
        return None
    print("[+] Located encrypted payload at starting file offset {}".format(Payload_Start))
    PayloadSize_StartOffset = Payload_Start + len(CryptAlgoPattern_bytes)
    PayloadSize_EndOffset = Payload_Start + len(CryptAlgoPattern_bytes) + 4
    PayloadStart = PayloadSize_EndOffset + 8 
    Start_Key = struct.unpack("<i",PlugxData[PayloadStart:PayloadStart+4])
    Encrypt_Payloadsize = struct.unpack("<i",PlugxData[PayloadSize_StartOffset:PayloadSize_EndOffset])
    Decrypt_Payload = DecryptAlgo(PlugxData[PayloadStart:],Encrypt_Payloadsize[0],Start_Key[0],Keys)

    return Decrypt_Payload

def DecompressModule(PlugXData):
    """
    IN: PlugX data to decompress
    OUT: Bytes of decompressed data

    Description:
    This function attempts to decompress the decrypted input file using RtlDecompressBuffer API. The compression is COMPRESSION_FORMAT_LZNT1
    """
    Decompressed = lznt1.decompress(PlugXData[16:])
    return Decompressed

def GetPlugxKeys(PlugxData):
    """
    IN: PlugX data to search.
    OUT: Dictionary of keys

    Description:
    Returns dictionary of keys to use for provided input file. Typically there are three different static keys that are either added or subtracted to specific values. Appears to be part
    of a PlugX builder
    """
    #The decryption algo starts off with shr ecx, 3 which gives us our start. This is for X86.
    Decrypt_Algo_StartBytes = binascii.unhexlify("C1E903") #shr eax, 3
    #Using find here versus RegEx as it's a simple search for SHR ECX, 3. All tested Plugx variants crypto routines start with this.
    Keys={}
    Decrypt_start = PlugxData.find(Decrypt_Algo_StartBytes)
    if Decrypt_start == -1:
        print("[-] Did not find decryption algo magic start bytes. Possible x64 or different variant")
        return False
    EIP = Decrypt_start
    #need to skip ahead a few bytes
    op_bytes = PlugxData[Decrypt_start + 6 : Decrypt_start + 6 + 7]

    #Intialize decoder, so we can dissassemble the bytes to get the constants. 32 = x86
    decoder = iced_x86.Decoder( 32 , PlugxData[Decrypt_start:],ip=EIP )
    FunctionCount = 0 #just incase we need to break out of the for loop
    KeyCount = 0 
    for instr in decoder:
        disasm = formatter.format(instr)
        if "jmp" in disasm or FunctionCount >120: #jmp should not exceed 120 instructions, so this is our safety net
            break
        op_code = instr.op_code()
        opstr = op_code.instruction_string
        if "LEA" in opstr:
            opInstructions=(f"{formatter.format_all_operands(instr)}")
            if "-" in opInstructions: #Most, if not all PlugX samples have substraction signed numbers
                dis=struct.pack("I",instr.memory_displacement)
                value=struct.unpack("<L",dis)[0]
                Keys[KeyCount]=-abs(value),"-"
            elif "+" in opInstructions:
                Keys[KeyCount]=(instr.memory_displacement),"+"
            KeyCount+=1 
        elif "ADD" in opstr and instr.len==6:
            Keys[KeyCount]=instr.immediate32,"+"
            KeyCount+=1
        elif "SUB" in opstr and instr.len==6:
            Keys[KeyCount]=instr.immediate32,"-"
            KeyCount+=1
        FunctionCount+=1

    return Keys

def WriteFile(InData,FileName):
    """
    IN: Data to save and Filename
    OUT: Bool True or False

    Description:
    Saves the data to the corresponding file
    """
    try:
        with open(FileName,"wb") as fp:
            fp.write(InData)
    except Exception as ex:
        print("[-] Error hit saving file {!r}".format(FileName))
        print(ex)
        return False

    return True

def ProcessPlugxXORFile(inFile,PlugxData,pos):
    """
    IN: PlugX data to decrypt.
    OUT: Bool True or False

    Description:
    Decrypts PlugX DAT file and assumes files are not compressed
    """
    PlugX_Decrypted = Decrypt_XOR( PlugxData,pos )
    if not PlugX_Decrypted:
        return False
    #XOR key used to decrypt embedded PlugX strings. Strings found in .data section of the module.
    Xor_Key = binascii.unhexlify("313233343536373839") #As if now appears to be a constant across all PlugX samples.
    count = 0
    i = 0
    Decrypt_Config=bytearray()
    try:
        pe = pefile.PE(data=PlugX_Decrypted)
    except Exception as ex:
        print("[-] Decrypted XOR input File not a PE, something went wrong")
        print("Error is ",ex)
        return False
    AlgoPattern=re.search(b"\x55\x8b\xec\x83\xec.\x68.{4}\x68",PlugX_Decrypted,re.DOTALL)
    if AlgoPattern:
        print(f"[+] Found encrypted payload offset at {AlgoPattern.regs[0][0]}")
        PayLoadSizeOffset = AlgoPattern.regs[0][0] + 7
        Encrypt_Size = struct.unpack("<i",PlugX_Decrypted[PayLoadSizeOffset:PayLoadSizeOffset+4])
        print(f"[+] Payload size is {Encrypt_Size[0]}")
        sections = pe.sections
        for section in sections:
            if section.Name ==b".data\x00\x00\x00":
                print("[+] Decrypting PE data section")
                #decrypt embedded config file
                ptr_raw_data = section.PointerToRawData
                while count < Encrypt_Size[0]:
                    enc_char = PlugX_Decrypted[ptr_raw_data]
                    if i>=len(Xor_Key):
                        i=0
                    PlugX_Decrypted[ptr_raw_data]=PlugX_Decrypted[ptr_raw_data]^Xor_Key[i]
                    Decrypt_Config.append(PlugX_Decrypted[ptr_raw_data])
                    i+=1
                    ptr_raw_data+=1
                    count+=1
                break
    else: #re.search returns None if not found
        print("[-] Did not locate crypto bytes in file. Possible x64 or unknown variant")
        return False
    FileName = pathlib.Path(inFile)
    NewFileName = FileName.with_suffix('._decrypt.dat')
    ConfigName = FileName.with_suffix('._C2Decrypt.dat')
    bRtnStatus = WriteFile(PlugX_Decrypted,NewFileName)
    if bRtnStatus:
        bRtnStatus = WriteFile(Decrypt_Config,ConfigName)
        if bRtnStatus:
            print ("[+] Wrote PlugX decrypted module and config {!r}{!r}".format(NewFileName,ConfigName))
    else:
        print ("[-] Failed to write decrypted module and config")

        return False

    return True

def AddMZHeader(inData):
    """
    IN: Input data to add MZ & PE Header
    OUT: Bytearray of module with updated header

    Description:
    This manually updates offsets of what I think the MZ and PE header are. MZ and PE are of a DLL. This should allow the file to load into IDA and parse correctly.
    """
    InData_Mutable=bytearray(inData)
    InData_Mutable[0:0x3c]    =    MZ_HEADER
    InData_Mutable[0x40:0xe2] =    PE_HEADER

    return InData_Mutable

def Decrypt_DatFile(PlugXFile):
    """
    IN: Input File to process. This is the PlugX file.
    OUT: BOOL True or False

    Description:
    This is the main function that will decrypt and decompress (if applicable) the PlugX file.
    """ 
    PlugxData = ReadInputFile(PlugXFile)
    if not PlugxData:
        #Something went wrong with reading input file.
        return False

    PlugxXORHeader,pos = CheckHeader(PlugxData)
    if PlugxXORHeader:
        #If file is PlugX XOR encrypted, decrypt and return.
        print ("[+] Found PlugX XOR Header in input file. Assuming input file is not compressed and XOR encrypted")
        bRtn = ProcessPlugxXORFile( PlugXFile, PlugxData,pos )
        return bRtn
    """
    If input file is compressed/encrypted we need to locate specific key values and they appear to be different for each Plugx file (possible Plugx builder)
    """

    PlugxKeys = GetPlugxKeys(PlugxData) #should return 4 keys
    if not PlugxKeys:
        print ("[-] Error input file does not appear to be plugx or is unknown")
        return False

    if len(PlugxKeys) !=4:
        print ("[-] Did not find all necessary crypto keys in input file.")
        return False
    #THOR or PLUG magic values found indicating callback is embedded in the DAT file. 
    PlugxEmbeddedConfig = CheckEmbeddedC2(PlugxData)
    if PlugxEmbeddedConfig:
         print ("[+] Hardcoded configuration (C2) data found")
         DumpConfig = DumpEmbeddedConfig(PlugxData,PlugxKeys)
         if DumpConfig:
            FileName = pathlib.Path(PlugXFile)
            NewFileName = FileName.with_suffix('._c2Decrypt.dat')
            bRtnStatus = WriteFile(DumpConfig,NewFileName)
            if bRtnStatus:
                print("[+] Wrote decrypted embedded C2 information to file {!r}".format(NewFileName))
            else:
                print("[-] Something went wrong trying to decrypt embedded C2 information. Continuing on to decrypting module")
    
    DumpModule = DecryptModule(PlugxData,PlugxKeys)
    if DumpModule:
        print ("[+] Successfully decrypted input file. Attempting to decompress file to module (DLL)")
        DecompressedMod = DecompressModule(DumpModule)
        if DecompressedMod:
            print ("[+] Successfully decompressed module.")
            if DecompressedMod[0]!=0x4d:
                print("[+] Adding MZ and PE header")
                Final_Data = AddMZHeader(DecompressedMod)
            else:
                Final_Data=DecompressedMod
            FileName = pathlib.Path(PlugXFile)
            NewFileName = FileName.with_suffix('._decompressed.dl_')
            bRtnStatus = WriteFile(Final_Data,NewFileName)
            if bRtnStatus:
                print ("[+] Saved decompressed file to {!r}".format(NewFileName))
            else:
                print("[-] Something went wrong attempting to save the decompress file")

    return True

def Logo():
    Banner= \
    """
        ██    ██ ███    ██ ██ ████████ ██   ██ ██████  
        ██    ██ ████   ██ ██    ██    ██   ██      ██ 
        ██    ██ ██ ██  ██ ██    ██    ███████  █████  
        ██    ██ ██  ██ ██ ██    ██         ██ ██      
         ██████  ██   ████ ██    ██         ██ ███████ 
                                               
                                               
    """
    return Banner

def Start():
    print ("{}".format(Logo()))
    print (f"{sys.argv[0]} Version {__version__[0]} {__version__[1]} {__version__[2]}")
    parser = argparse.ArgumentParser(usage="%(prog)s PlugX inputfile",description='Process PlugX DAT File')
    #need nargs to handle spaces in input file
    parser.add_argument("PlgxInputfile",type=str,help="PlugX encrypted input file to Decrypt/Decompress",nargs='+')
    args = parser.parse_args()
    if args.PlgxInputfile:
        #handle if input file contains a space as argparser will throw an error.
        Decrypt_DatFile(' '.join(args.PlgxInputfile))

    print("[+] Finished")