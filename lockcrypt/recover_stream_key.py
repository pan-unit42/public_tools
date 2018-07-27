#!/usr/bin/env python

import argparse
import io
import os
import struct
import sys

def ror(val, n, width):
    return ((val & ((1<<width)-1)) >> n) | \
           (val << (width-n) & ((1<<width)-1))

key_len = 25000

def recover_stream_key(plain, enc, idx):
    plain.seek(0, os.SEEK_END)
    plain_len = plain.tell()
    plain.seek(0, os.SEEK_SET)

    enc.seek(0, os.SEEK_END)
    enc_len = enc.tell()
    enc.seek(0, os.SEEK_SET)

    if plain_len != enc_len:
        print "[-] plaintext file and encrypted file are not of the same length!"
        return None

    if plain_len -1 < idx + key_len:
        print "[-] requested stream key idx is too large for the given file size!"
        return None

    if plain.read(4) != enc.read(4):
        print "[-] first 4 bytes in file pair do not match -- seems like this is not the encrypted version of the given plaintext file"

    plain.seek(idx & (~3), os.SEEK_CUR)
    enc.seek(idx & (~3), os.SEEK_CUR)

    stream_key = io.BytesIO()
    for i in xrange(0, key_len + (idx % 4), 4):
        p = plain.read(4)
        p = struct.unpack("<I", p)[0]

        e = enc.read(4)
        e = struct.unpack(">I", e)[0]
        e = ror(e, 5, 32)

        k = p^e
        k = struct.pack("<I", k)

        if i == 0:
            stream_key.write(k[idx % 4:])
        elif i < key_len:
            stream_key.write(k)
        else: # i == key_len
            stream_key.write(k[:idx % 4])
    stream_key = stream_key.getvalue()

    assert len(stream_key) == key_len

    print "[+] done!"

    return stream_key

def parse_args():
    parser = argparse.ArgumentParser(description="this scripts recovers the 'stream key' for a given index from a file encrypted the LockCrypt ransomware, given its plaintext version")

    parser.add_argument("plain", metavar="plain_path", help="the path to the plaintext file", type=argparse.FileType('rb'))
    parser.add_argument("enc", metavar="enc_path", help="the path to the encrypted file", type=argparse.FileType('rb'))
    parser.add_argument("idx", metavar="index", help="the stream key index to recover", type=int)
    parser.add_argument("stream_key", metavar="stream_key_path", help="the path to write the recovered stream key to", type=argparse.FileType('wb'))

    args = parser.parse_args()

    if args.idx < 0:
        parser.error("idx must be a non-negative number")
        sys.exit(1)

    return args

if __name__ == "__main__":
    args = parse_args()

    try:
        stream_key = recover_stream_key(args.plain, args.enc, args.idx)

        if stream_key is None:
            print "[-] failed to recover stream key!"
        else:
            args.stream_key.write(stream_key)
    except IOError as e:
        print "[-] IO error: {}".format(e)
