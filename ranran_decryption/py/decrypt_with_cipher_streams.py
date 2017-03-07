import base64
from binascii import *
import hashlib
import sys
import os
import os.path
from optparse import OptionParser
from binascii import *
from struct import *
import glob


def xor_two_files(f1, f2):
  out = ''
  r = len(f1)
  if len(f2) < r:
    r = len(f2)
  for x in range(r):
    out += chr(ord(f1[x]) ^ ord(f2[x]))
  return out


parser = OptionParser()
parser.add_option("-d", "--dir", dest="directory",
                  help="decrypt specified directory")
parser.add_option("-i", "--stream-dir", dest="stream_directory",
                  help="input for collected cipher streams")

(options, args) = parser.parse_args()

if not options.directory:   
  parser.error('Decrypt directory not supplied')

if not options.stream_directory:   
  parser.error('Cipher stream directory not supplied')

decrypt_directory = options.directory
stream_directory = options.stream_directory

if not os.path.isdir(stream_directory):
  print("[*] Cipher stream directory doesn't exist. Exiting now.")
  sys.exit(1)

streams_0_5 = []

for g in glob.glob(os.path.join(stream_directory, "*.stream.0_5")):
  f = open(g, 'rb')
  fd = f.read()
  f.close()
  streams_0_5.append(fd)

print("[+] Pulled {} streams 0-5 from output folder.".format(len(streams_0_5)))

streams_5_30 = []

for g in glob.glob(os.path.join(stream_directory, "*.stream.5_30")):
  f = open(g, 'rb')
  fd = f.read()
  f.close()
  streams_5_30.append(fd)

print("[+] Pulled {} streams 5-30 from output folder.".format(len(streams_5_30)))

streams_30_100 = []

for g in glob.glob(os.path.join(stream_directory, "*.stream.30_100")):
  f = open(g, 'rb')
  fd = f.read()
  f.close()
  streams_30_100.append(fd)

print("[+] Pulled {} streams 30-100 from output folder.".format(len(streams_30_100)))

streams_100_300 = []

for g in glob.glob(os.path.join(stream_directory, "*.stream.100_300")):
  f = open(g, 'rb')
  fd = f.read()
  f.close()
  streams_100_300.append(fd)

print("[+] Pulled {} streams 100-300 from output folder.".format(len(streams_100_300)))


streams_300_700 = []

for g in glob.glob(os.path.join(stream_directory, "*.stream.300_700")):
  f = open(g, 'rb')
  fd = f.read()
  f.close()
  streams_300_700.append(fd)

print("[+] Pulled {} streams 300-700 from output folder.".format(len(streams_300_700)))


streams_700_2000 = []

for g in glob.glob(os.path.join(stream_directory, "*.stream.700_2000")):
  f = open(g, 'rb')
  fd = f.read()
  f.close()
  streams_700_2000.append(fd)

print("[+] Pulled {} streams 700-2000 from output folder.".format(len(streams_700_2000)))


streams_2000_3000 = []

for g in glob.glob(os.path.join(stream_directory, "*.stream.2000_3000")):
  f = open(g, 'rb')
  fd = f.read()
  f.close()
  streams_2000_3000.append(fd)

print("[+] Pulled {} streams 2000-3000 from output folder.".format(len(streams_2000_3000)))


streams_3000_ = []

for g in glob.glob(os.path.join(stream_directory, "*.stream.3000_")):
  f = open(g, 'rb')
  fd = f.read()
  f.close()
  streams_3000_.append(fd)

print("[+] Pulled {} streams 3000- from output folder.".format(len(streams_3000_)))


def decrypt_file_with_stream(zxz_file, streams):
  c = 0
  og_prefix = zxz_file.split(".")[-2]
  for stream in streams:
    nfile = "{}.{}.{}".format(zxz_file, str(c), og_prefix)
    nfh = open(nfile, 'wb')
    ofh = open(zxz_file, 'rb')
    zxz_data = ofh.read()
    ofh.close()

    nfh.write(xor_two_files(zxz_data, stream))
    nfh.close()
    print("[+] Wrote {}".format(nfile))
    c+=1


for root, dirs, files in os.walk(options.directory):
  for file in files:
    if file.endswith(".zXz"):
      zxz_file = os.path.join(root, file)
      try:
        fh = open(zxz_file, 'rb')
        zxz_data = fh.read()
        fh.close()
        if len(zxz_data) > 0:
          if zxz_data[0:4] != "\x00\x00\x00\x00":
              if len(zxz_data) < (5*1024*1024):
                decrypt_file_with_stream(zxz_file, streams_0_5)
              elif len(zxz_data) < (30*1024*1024):
                decrypt_file_with_stream(zxz_file, streams_5_30)
              elif len(zxz_data) < (100*1024*1024):
                decrypt_file_with_stream(zxz_file, streams_30_100)    
              elif len(zxz_data) < (300*1024*1024):
                decrypt_file_with_stream(zxz_file, streams_100_300)
              elif len(zxz_data) < (700*1024*1024):
                decrypt_file_with_stream(zxz_file, streams_300_700) 
              elif len(zxz_data) < (2000*1024*1024):
                decrypt_file_with_stream(zxz_file, streams_700_2000) 
              elif len(zxz_data) < (3000*1024*1024):
                idecrypt_file_with_stream(zxz_file, streams_2000_3000)  
              else:
                decrypt_file_with_stream(zxz_file, streams_3000_)   
      except Exception as e:
        pass