#!/usr/bin/env python

import argparse
import io
import itertools
import logging
import os
import shutil
import stat
import struct
import sys

ENC_EXTS = [".2018", ".1btc", ".1BTC", ".mich", ".lock"]
RANSOM_NOTE_FILENAMES = ["Restore Files.TxT", "Attention!!!.TxT", "ReadMe.TxT"]
RANSOM_NOTE_SNIPPETS = ["have been encrypted"]

# blob decryption

def grouper(iterable, n, fillvalue=None):
    args = [iter(iterable)] * n
    return itertools.izip_longest(fillvalue=fillvalue, *args)

def ror(val, n, width):
    return ((val & ((1<<width)-1)) >> n) | \
           (val << (width-n) & ((1<<width)-1))

def decrypt(enc, key):
    if len(enc) < 4:
        return enc

    size = len(enc)-2
    plain = io.BytesIO(enc)

    # phase 2
    key_cyclic = grouper(itertools.cycle(key), 4)
    for i in xrange(0, size&(~3), 4):
        k = "".join(key_cyclic.next())
        k = struct.unpack("<I", k)[0]

        e = plain.read(4)
        e = struct.unpack(">I", e)[0]

        d = e^k
        d = ror(d, 5, 32)
        d = struct.pack("<I", d)

        plain.seek(-4, os.SEEK_CUR)
        plain.write(d)

    # phase 1
    plain.seek(size&(~0x3), os.SEEK_SET)
    key_cyclic = grouper(itertools.cycle(key), 4)
    key_cyclic = reversed(list(itertools.islice(key_cyclic, ((size&(~0x3))>>1))))
    for i in xrange(0, size&(~0x3), 2):
        k = "".join(key_cyclic.next())
        k = struct.unpack("<I", k)[0]

        plain.seek(-2, os.SEEK_CUR)
        e = plain.read(4)
        e = struct.unpack("<I", e)[0]

        d = k^e
        d = struct.pack("<I", d)

        plain.seek(-4, os.SEEK_CUR)
        plain.write(d)
        plain.seek(-4, os.SEEK_CUR)

    return plain.getvalue()

# file decryption

def decrypt_filename(key, filename, args):
    filename, ext = os.path.splitext(filename)

    try:
        dec_filename, computer_id = filename.split(" ID-")

        logging.info("[*] filename was not apparently encrypted since it was long")
        return dec_filename
    except ValueError:
        pass # not a non-encrypted filename

    try:
        enc_filename_b64, computer_id = filename.split(" ID ")
    except ValueError:
        logging.error("[-] encrypted filename seems to be invalid (unexpected structure)")
        return None

    try:
        enc_filename_b64 = enc_filename_b64.replace('-', '/')
        enc_filename = enc_filename_b64.decode('base64')
    except Exception:
        logging.error("[-] encrypted filename seems to be invalid (base64 decoding failed)")
        return None

    # decrypt the filename by XOR-ing to the key from offset 11111
    dec_filename = "".join(chr(ord(e) ^ ord(k)) for e, k in zip(enc_filename, key[11111:]))

    try:
        dec_filename = dec_filename.decode('utf-16')
    except UnicodeDecodeError:
        logging.error("[-] decrypted filename seems to have the wrong encoding")
        return None

    return dec_filename

def decrypt_file(key, enc_path, args):
    assert os.path.isfile(fsencode(enc_path))

    dirname, enc_filename = os.path.split(enc_path)

    dec_filename = decrypt_filename(key, enc_filename, args)
    if dec_filename is None:
        logging.error("[-] skipping file decryption")
        return
    else:
        logging.info("[+] decrypted the filename to '{}'".format(fsencode(dec_filename)))

    dec_path = os.path.join(dirname, dec_filename)

    if os.path.exists(fsencode(dec_path)):
        logging.error("[-] decrypted path already exists, skipping")
        return

    if args.decrypt_in_place:
        try:
            os.chmod(fsencode(enc_path), stat.S_IWRITE)
        except OSError as e:
            logging.error("[-] failed to set the file to writable: {}".format(e))
            return

        try:
            os.rename(fsencode(enc_path), fsencode(dec_path))
            logging.info("[+] renamed to the original filename")
        except OSError as e:
            logging.error("[-] failed to rename to the original file name: {}".format(e))
            return

        try:
            with open(fsencode(dec_path), "rb+") as file:
                logging.info("[*] decrypting file contents in place...")

                file.seek(4, os.SEEK_SET)
                enc_data = file.read(0x100000 - 4)

                dec_data = decrypt(enc_data, key)
                assert len(enc_data) == len(dec_data)

                file.seek(4, os.SEEK_SET)
                file.write(dec_data)

            logging.info("[+] done!")
        except IOError as e:
            logging.error("[-] failed an IO operation: {}. stopping decryption".format(e))
            return
    else:
        try:
            with open(fsencode(enc_path), "rb") as enc_file, open(fsencode(dec_path), "wb") as dec_file:
                logging.info("[*] decrypting file contents...")

                # copy the 4 bytes prefix
                dec_file.write(enc_file.read(4))

                # decrypt the first 1MB
                enc_data = enc_file.read(0x100000 - 4)
                dec_data = decrypt(enc_data, key)
                assert len(enc_data) == len(dec_data)
                dec_file.write(dec_data)

                logging.info("[*] copying the unencrypted portion of the file...")

                # copy the rest of the file
                while True:
                    chunk = enc_file.read(32<<10)
                    if len(chunk) == 0:
                        break
                    dec_file.write(chunk)

            logging.info("[+] done!")
        except IOError as e:
            logging.error("[-] failed an IO operation: {}. stopping decryption".format(e))
            return

        try:
            shutil.copymode(fsencode(enc_path), dec_path)
            shutil.copystat(fsencode(enc_path), dec_path)
        except (IOError, OSError) as e:
            logging.error("[-] failed to copy file metadata to the decrypted file: ".format(e))
            return

        if args.delete_source_files:
            try:
                os.chmod(fsencode(enc_path), stat.S_IWRITE)
                os.unlink(fsencode(enc_path))
                logging.info("[+] removed encrypted file")
            except OSError as e:
                logging.error("[-] failed to remove the encrypted file: {}".format(e))

def remove_ransom_note(path, args):
    try:
        with open(path, "rb") as f:
            ransom_note = f.read(1024)
    except IOError as e:
        logging.error("[-] failed to read the supposed ransom note file: {}".format(e))
        return

    if any(snip in ransom_note for snip in RANSOM_NOTE_SNIPPETS):
        try:
            os.chmod(fsencode(path), stat.S_IWRITE)
            os.unlink(fsencode(path))
            logging.info("[+] removed ransom note file")
        except OSError as e:
            logging.error("[-] failed to remove the ransom note file: {}".format(e))
    else:
        logging.error("[-] file does not contain any known ransom note snippets. skipping")

def is_supposed_enc_file(filename):
    return os.path.splitext(filename)[1] in ENC_EXTS

def is_supposed_ransom_note_file(filename):
    return filename in RANSOM_NOTE_FILENAMES

def decrypt_dir(key, rootpath, args):
    assert os.path.isdir(fsencode(rootpath))

    def walk_error_handler(error):
        logging.error("[-] failed to traverse to '{}': {}. skipping...".format(fsencode(error.filename), error))

    for dirpath, dirnames, filenames in os.walk(rootpath, onerror=walk_error_handler):
        for filename in filenames:
            path = os.path.join(dirpath, filename)

            if is_supposed_enc_file(filename):
                logging.info("[+] found a seemingly encrypted file: '{}'".format(fsencode(path)))
                decrypt_file(key, path, args)
                logging.info("")
            elif args.delete_ransom_notes and is_supposed_ransom_note_file(filename):
                logging.info("[+] found a supposed ransom note file: '{}'".format(fsencode(path)))
                remove_ransom_note(path, args)
                logging.info("")

def fsencode(u):
    return u.encode(sys.getfilesystemencoding())

def fsdecode(s):
    return s.decode(sys.getfilesystemencoding())

# command line

def parse_args():
    parser = argparse.ArgumentParser(description="this scripts decrypts files encrypted by the LockCrypt ransomware, given the encryption key")

    parser.add_argument("path", help="a path to the file/directory-tree to decrypt")
    parser.add_argument("-k", "--key", help="a path to the recovered key file", type=argparse.FileType("rb"), required=True)
    parser.add_argument("--delete-ransom-notes", help="delete found ransom notes", action="store_true")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--delete-source-files", help="delete the encrypted files after successful decryption", action="store_true")
    group.add_argument("--decrypt-in-place", help="decrypt the file in place. useful if we fail to write the decrypted file because of permissions (warning: might be destructive if something goes wrong)", action="store_true")
    parser.add_argument("--log", help="save the output to a log file")

    args = parser.parse_args()

    # normalize the path and make it extended
    if not os.path.exists(args.path):
        parser.error("the given path does not exist")
    args.path = fsdecode(args.path)
    args.path = os.path.abspath(fsencode(args.path))
    if not args.path.startswith(u"\\\\?\\"):
        args.path = u"\\\\?\\" + args.path

    # verify the key length
    args.key.seek(0, os.SEEK_END)
    if args.key.tell() != 25000:
        parser.error("the key file must be exactly {} bytes long".format(25000))
    args.key.seek(0, os.SEEK_SET)

    return args

def setup_logger(args):
    formatter = logging.Formatter(fmt="[%(asctime)s] %(message)s", datefmt="%d-%m-%Y %H:%M:%S")
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    if args.log is not None:
        try:
            file_handler = logging.FileHandler(args.log, mode="w")
            file_handler.setFormatter(formatter)
        except IOError:
            logging.error("failed to open log file for writing")
            sys.exit(1)
        root_logger.addHandler(file_handler)

if __name__ == "__main__":
    args = parse_args()
    setup_logger(args)

    key = args.key.read()

    if os.path.isfile(fsencode(args.path)):
        decrypt_file(key, args.path, args)
    else:
        decrypt_dir(key, args.path, args)
        logging.info("[+] done decrypting the requested directory")
