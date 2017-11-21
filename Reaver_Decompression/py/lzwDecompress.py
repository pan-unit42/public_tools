#-------------------------------------------------------------------------------
# Name:        LzwDecompression
# Purpose:
#
# Author:      Mike Harbison Unit 42
#
# Created:     27/10/2017
#-------------------------------------------------------------------------------

from ctypes import *
import sys
import os.path
import argparse
import re,struct
import subprocess, random

# MAP types to ctypes
LPBYTE = POINTER(c_ubyte)
LPCSTR = LPCTSTR = c_char_p
BOOL = c_bool

if os.name != 'nt':
    print ("Script can only be run from Windows")
    sys.exit("Sorry Windows only")

def assert_success(success):
    if not success:
        raise AssertionError(FormatError())

def LzwDecompress(hdll,data):
    inbuf = create_string_buffer(data)
    outbuf= create_string_buffer(len(data))
    success = hdll.Decompress(inbuf,outbuf)
    assert_success(success)
    return outbuf.raw

def CabExtract(match,pargs,data):
    offset = match.start()
    CabHeaderMagicValue = offset + 124
    CabSizeStart = offset + 132
    CabFileNameStart = offset + 184
    CabFileNameEnd = data[CabFileNameStart:].find('\0')
    CabName = data[CabFileNameStart:CabFileNameStart+CabFileNameEnd]
    CabSize = struct.unpack("L",data[CabSizeStart:CabSizeStart+4])[0]
    CabData = data[CabHeaderMagicValue:CabHeaderMagicValue+CabSize]
    FileName=pargs.input_file
    #Add magic value
    Cab="4D534346".decode('hex')+CabData[4:]
    print "Found our CAB Data at file offset-->{}".format(offset)
    CabDir=os.path.splitext(FileName)[0]
    if not os.path.exists(CabDir):
        os.makedirs(CabDir)
    else:
        CabDir+='_'+str(random.randint(1111,9999))
        os.makedirs(CabDir)
    CabFile=os.path.basename(FileName).split('.')[0]+".cab"
    with open(CabDir+"\\"+CabFile,"wb") as fp:
        fp.write(Cab)
    print "Wrote CAB File-->%s"%CabDir+"\\"+CabFile
    print "Expanding CAB File %s"%CabName
    args = [" -r ",CabDir + "\\" + CabFile,' ',CabDir]
    result=subprocess.Popen("expand "+"".join(args), stdout=subprocess.PIPE)
    result.wait()
    if "Expanding Files Complete" not in result.stdout.read():
        print "Error Expanding CAB file"
        sys.exit(1)
    ExpandedFile = CabDir + "\\" + CabName
    if not os.path.isfile(ExpandedFile):
        print "Did not find our expanded file %s"%CabName
        sys.exit(1)

    print "Check directory %s for expanded file %s"%(CabDir,CabName)
    return ExpandedFile

def DecompressRoutine(pargs,hlzw,data):
    LzwCompPattern = "\x08\x00\xA5\x04\x01\x12\x03"
    regex = re.compile(LzwCompPattern)
    for match in regex.finditer(data):
        offset=match.start()
        print "Found our compression header at file offset-->{}".format(offset)
        Deflated=LzwDecompress(hlzw,data[offset:])
        if Deflated:
            with open(pargs.out_file, "wb") as wp:
                wp.write(Deflated)
            print "Wrote decompressed stream to file-->%s"%(pargs.out_file)
            return True
    return False


def Start(pargs,hlzw,data):
    CabCompPattern = bytearray("46444944657374726F790000464449436F7079004644494973436162696E657400000000464449437265617465000000636162696E65742E646C6C004D6963726F736F6674")
    #Check For CAB file magic value first
    found = False
    regex = re.compile(CabCompPattern.decode('hex'))
    for match in regex.finditer(data):
        found = True
        ExpandedFile=CabExtract(match,pargs,data)
        if ExpandedFile:
            with open(ExpandedFile,"rb") as fp:
                ExpandedData=fp.read()
                DecompressRoutine(pargs,hlzw,ExpandedData)
            return True
    if not found:
        result=DecompressRoutine(pargs,hlzw,data)
        if result:
            return True
        else:
            return False

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("-i", '--infile' , dest='input_file',help="Input file to process",required=True)
    parser.add_argument("-o", '--outfile', dest='out_file',help="Optional Output file name",required=False)
    results = parser.parse_args()
    if not results.out_file:
        results.out_file=results.input_file + "_dec.txt"
    lzwdll="LzwDecompress.dll"
    lzwdllpath = os.path.dirname(os.path.abspath(__file__)) + os.path.sep + lzwdll
    if os.path.isfile(lzwdllpath):
        lzw = windll.LoadLibrary(lzwdllpath)
        lzw.Decompress.argtypes=(LPCSTR,LPCSTR)
        lzw.Decompress.restypes=BOOL
    else:
        print ("Missing LzwDecompress.DLL")
        sys.exit(1)

    with open(results.input_file,"rb") as fp:
        FileData=fp.read()
        Success=Start(results,lzw,FileData)
        if not Success:
            print("Did not find CAB or Compression routine in file %s")%(results.input_file)

if __name__ == '__main__':
    main()