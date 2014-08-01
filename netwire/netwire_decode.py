"""
Program to decode netwire traffic based on the initial exchange of keys.

author = Unit 42
copyright = 'Copyright 2014, Palo Alto Networks'
"""
import argparse
import binascii
import json
import socket
import string
import sys

import Crypto.Util.Counter
from Crypto.Cipher import AES
import dpkt

PASSWORD = 'Password'
BS = 16

pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

def create_key ( password, seed ):
    ## seed is assumed to be hex
    flip = ''
    result = ''

    # This will flip the lower and upper order nibbles
    for i in password:
        i_bin = binascii.hexlify(i)
        tmp = i_bin[1] + i_bin[0]
        flip += tmp

    result += binascii.unhexlify(flip)

    for i in xrange(8, 32):
        tmp = i >> 5 | i * 8
        tmp = tmp & i
        result += chr(tmp)

    a1 = ord(result[len(password) >> 2]) ^ len(password)

    for i in xrange(0, 32):
        v4 = ord(result[i]) ^ ord(seed[i])
        v10 = a1 ^ v4
        v10 = v10 & 0xFF

        v11 = 4 * v10

        #only the low byte gets changed below
        v11 = ord( seed[i] ) ^ ( 4 * v10 )

        a1 = ~v11 & 0xFFF

        v4 = (i ^ (i + len(password))) | (v10 >> 5) | (8 * v10)
        v4 = v4 & 0xFF
        v4 = hex(v4)[2:].zfill(2)
        v4 = binascii.unhexlify(v4)

        pieces = list(result)
        pieces[i] = str(v4)
        result = "".join(pieces)

    return result


def encrypt( raw, key, iv ):
    """
    Encrypt the raw data using the provided key and initial IV.  Data will be 
    encrypted using AES OFB mode.
    
    Args:
        raw: plaintext data to be encrypted
        key: AES key used for encryption
        iv: Initial IV used for encryption
    """
    result = ''
    tmp_iv = iv 
    text = pad(raw)

    for i in xrange(0, len(text) / BS):
        lower_bound = i * 16
        upper_bound = (i+1) * 16
        
        tmp = AES.new(key, AES.MODE_OFB, tmp_iv).decrypt( text[lower_bound:upper_bound] )
        tmp_iv = tmp
        result += tmp

    return result


def decrypt( raw, key, iv ):
    """
    Decrypt the raw data using the provided key and iv.  
    Netwire encrypts data using AES OFB mode.  Initial IV is sent in the key exchange
    packet.  This iv will decrypt the initial block of 16 bytes of data, each 
    subsequent block will use the previous block as an IV.
    
    Args:
        raw: raw data to be decrypted
        key: AES key used to decrypt the data
        iv: initial IV used for decryption
    """
    result = ''
    tmp_iv = iv 
    ciphertext = pad(raw)

    for i in xrange(0, len(ciphertext) / BS):
        lower_bound = i * 16
        upper_bound = (i+1) * 16
        
        tmp = AES.new(key, AES.MODE_OFB, tmp_iv).decrypt( ciphertext[lower_bound:upper_bound] )
        tmp_iv = ciphertext[lower_bound:upper_bound]
        result += tmp

    return result


def command_conversion(dest, command, payload):
    """
    Convert the command info (if known).
    http://www.circl.lu/pub/tr-23/
    Args:
        dest: a string containing either 'server' or 'client' to dictate which direction the packet is going.
        command: hex string of the command byte
        payload: hest string of the packet payload data
    
    """
    decoded_text = ''
    
    json_data = open('./commands.json')
    json_commands = json.load(json_data)
    command_string = binascii.hexlify(command).upper()
    
    if json_commands.has_key(command_string):
        decoded_text = json_commands[command_string]
    else:
        decoded_text = ''
    
    return decoded_text, payload


def decode_command( dest, command, payload):
    """
    Print out the command info response from command_conversion.
    Args:
        dest: a string containing either 'server' or 'client' to dictate which direction the packet is going.
        command: hex string of the command byte
        payload: hest string of the packet payload data
    
    """
    decoded_text, payload = command_conversion(dest, command, payload)
    
    if (dest == 'server'):
        print 'client -> server'
        print 'Command: %s => %s' % (binascii.hexlify(command), decoded_text)
        print 'Payload: %r \n' % ( payload )
    else:
        print 'server -> client'
        print 'Command: %s => %s' % (binascii.hexlify(command), decoded_text)
        print 'Payload: %r \n' % ( payload )
        
    pass


def parse_args():
    global PASSWORD

    ap = argparse.ArgumentParser('%prog [OPTIONS]', description='decode netwire traffic based on key exchange packets')

    ap.add_argument("-P", "--password", dest="password", help="password used to create AES key", metavar="Password")
    ap.add_argument("-f", "--file", dest="pcap", help="pcap file to parse", metavar="")
    ap.add_argument("-p", "--port", dest="port", help="port that netwire server is on", metavar="")
    ap.add_argument("-i", "--ip", dest="ip", help="ip address that netwire client is on", metavar="")

    args = ap.parse_args()

    if args.password:
        PASSWORD = args.password
    if not(args.port):
        print "[x] a port is required"
        sys.exit(1)
    if not(args.ip):
        print "[x] a client ip is required"
        sys.exit(1)
    if not(args.pcap):
        print "[x] a pcap file is required"
        sys.exit(1)
    return args


def main():
    global PASSWORD

    args = parse_args()
    print "[i] Starting ..."
    
    client_key_set = False
    server_key_set = False

    if args.pcap:
        f = open(args.pcap)
        pcap = dpkt.pcap.Reader(f)
    else:
        sys.exit(1)

    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except dpkt.dpkt.NeedData:
            continue
        
        ip = eth.data
        # Verify that the packet is an IP packet
        if type(ip) != dpkt.ip.IP:
            continue
        
        tcp = ip.data
        # Verify that the packet is a TCP packet
        if type(tcp) != dpkt.tcp.TCP:
            continue
        
        payload = tcp.data
        
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        
        if src_ip == args.ip:
            if str(tcp.dport) == args.port:
                # Client to Server Comms
                if payload == '':
                    continue
                
                command = payload[4]
                
                if command == '\x03':
                    client_seed = payload[5:37]
                    client_iv = payload[37:53]
                    client_key = create_key(PASSWORD, client_seed)
                    client_key_set = True
                    print '[i] Client Key Generated'
                elif client_key_set == False:
                    continue
                else:
                    tmp = decrypt(payload[5:], client_key, client_iv)
                    decode_command('server', command, tmp)
                    pass
                
                pass
        
        if dst_ip == args.ip:
            if str(tcp.sport) == args.port:
                # Server to Client Comms
                if payload == '':
                    continue
                
                command = payload[4]
                
                if command == '\x05':
                    server_seed = payload[5:37]
                    server_iv = payload[37:53]
                    server_key = create_key(PASSWORD, server_seed)
                    server_key_set = True
                    print '[i] Server Key Generated'
                elif server_key_set == False:
                    continue
                else:
                    tmp = decrypt(payload[5:], server_key, client_iv)
                    decode_command('client', command, tmp)
                    pass
                
                pass
        
    f.close()

if __name__ == '__main__':
    main()
