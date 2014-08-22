"""
Program to decode netwire traffic based on the initial exchange of keys.

author = Unit 42
copyright = 'Copyright 2014, Palo Alto Networks'
"""
import binascii
import json
import struct

from Crypto.Cipher import AES

moduleName = "netwire"
moduleVersion = "0.1"
minimumChopLib = "4.0"
author = "unit 42"

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


def command_conversion(dest, command, payload, command_list):
    """
    Convert the command info (if known).
    http://www.circl.lu/pub/tr-23/
    Args:
        dest: a string containing either 'server' or 'client' to dictate which direction the packet is going.
        command: hex string of the command byte
        payload: hest string of the packet payload data
    
    """
    decoded_text = ''
    
    json_commands = json.loads(command_list)
    command_string = binascii.hexlify(command).upper()
    
    if json_commands.has_key(command_string):
        decoded_text = json_commands[command_string]
    else:
        decoded_text = ''
    
    return decoded_text, payload


def decode_command( dest, command, payload, command_list):
    """
    Print out the command info response from command_conversion.
    Args:
        dest: a string containing either 'server' or 'client' to dictate which direction the packet is going.
        command: hex string of the command byte
        payload: hest string of the packet payload data
    
    """
    decoded_text, payload = command_conversion(dest, command, payload, command_list)
    
    if (dest == 'server'):
        chop.tsprnt('client -> server')
        chop.tsprnt('Command: %s => %s' % (binascii.hexlify(command), decoded_text))
        chop.tsprnt('Payload: %r \n' % ( payload ))
    else:
        chop.tsprnt('server -> client')
        chop.tsprnt('Command: %s => %s' % (binascii.hexlify(command), decoded_text))
        chop.tsprnt('Payload: %r \n' % ( payload ))


def module_info():
    return "A module to dump decoded netwire packet payloads from a stream.\nMeant to be used to decode traffic from that Remote Administration Tool (RAT)."


def init(module_data):
    module_options = { 'proto': [{'tcp': ''}] }
    module_data['password'] = 'Password'
    module_data['commands'] = """
{
    "01": "heartbeat",
    "02": "Socket created",
    "03": "registered",
    "04": "setting password failed",
    "05": "set password, identifier and fetch computer information such as user, computername, windows version",
    "06": "create process from local file or fetch from URL first and create process",
    "07": "create process from local file and exit",
    "08": "failed to create process",
    "09": "stop running threads, cleanup, exit",
    "0A": "stop running threads, cleanup, sleep",
    "0B": "stop running threads, delete autostart registry keys, cleanup, exit",
    "0C": "add identifier, IE .Identifier file",
    "0D": "Download file over HTTP to TEMP and execute",
    "0E": "fetch and send logical drives and types",
    "0F": "Failed to obtain logical drive info",
    "10": "locate and send file with time, attributes and size",
    "12": "find file",
    "13": "file information",
    "14": "unset tid for 0x12",
    "14": "file not found",
    "15": "send file",
    "16": "write into file",
    "17": "close file",
    "18": "copy file",
    "19": "execute file",
    "1A": "move file",
    "1B": "delete file",
    "1C": "create directory",
    "1D": "file copy",
    "1E": "create directory or send file to server",
    "1F": "close file",
    "20": "start remote shell",
    "21": "write into WritePipe",
    "22": "reset tid for remote shell",
    "22": "terminated remote shell",
    "23": "failed to start remote shell",
    "24": "collect client information and configuration",
    "25": "failed to get client information and configuration",
    "26": "get logged on users",
    "26": "send logged on users",
    "27": "failed to send logged on users",
    "28": "get detailed process information",
    "29": "failed to get detailed process information",
    "2A": "terminate process",
    "2B": "enumerate windows",
    "2B": "send windows",
    "2C": "make window visible, invisible or show text",
    "2D": "get file over HTTP and execute",
    "2E": "HTTP connect failed",
    "2F": "set keyboard event 'keyup'",
    "30": "set keyboard event $event",
    "31": "set mouse button press",
    "32": "set cursor position",
    "33": "take screenshot and send",
    "35": "failed to take screenshot",
    "36": "locate and send file from log directory with time, attributes and size",
    "38": "check if log file exists",
    "39": "delete logfile",
    "3A": "read key log file and send",
    "3C": "failed to read key log file",
    "3D": "fetch and send stored credentials, history and certificates from common browsers",
    "3E": "fetch and send stored credentials, history and certificates from common browsers",
    "3F": "fetch and send chat Windows Live, Pidgin credentials",
    "40": "fetch and send chat Windows Live, Pidgin credentials",
    "41": "fetch and send mail Outlook, Thunderbird credentials and certificates",
    "42": "fetch and send mail Outlook, Thunderbird credentials and certificates",
    "43": "socks_proxy",
    "44": "get audio devices and formats",
    "44": "audio devices and formats",
    "45": "failed to get audio devices",
    "46": "start audio recording",
    "47": "error during recording",
    "48": "stop audio recording",
    "49": "find file get md5",
    "4C": "unset tid for find file get md5",
    "80": "continuation of file download"
}
"""
    return module_options


def handleStream(tcp):
  chop.tsprnt('--------------------------------')
  chop.tsprnt("addr: %s" %  str(tcp.addr))
  chop.tsprnt("Server Count: %s" % tcp.server.count_new)
  chop.tsprnt("Client Count: %s" % tcp.client.count_new)
  chop.tsprnt("Server offset: %s" % tcp.server.offset)
  chop.tsprnt("Client offset: %s" % tcp.client.offset)
  chop.tsprnt('')

  if (tcp.client.count_new >= 5):
    len_client = struct.unpack('<I', tcp.client.data[0:4])[0]
    command_client = tcp.client.data[4]

    if tcp.client.data[4] == '\x05':
      server_seed = tcp.client.data[5:37]
      server_iv = tcp.client.data[37:53]
      server_key = create_key(tcp.module_data['password'], server_seed)

      tcp.module_data['server_key'] = server_key
      tcp.module_data['server_iv'] = server_iv

      tcp.discard(tcp.client.count_new)
      chop.tsprnt("Server Key Generated")
      chop.tsprnt('')
      return

    elif not(tcp.module_data.has_key('server_key')):
      chop.tsprnt('Skipping')
      tcp.discard(tcp.client.count_new)
      return

    else:
      if (len_client == 1):
        decode_command('server', command_client, '', tcp.module_data['commands'])
        return
      
      tmp = decrypt(tcp.client.data[5:tcp.client.count_new], tcp.module_data['server_key'], tcp.module_data['client_iv'])
      decode_command('server', command_client, tmp, tcp.module_data['commands'])
      return

  if (tcp.server.count_new >= 5):
    len_server = struct.unpack('<I', tcp.server.data[0:4])[0]
    command_server = tcp.server.data[4]

    if tcp.server.data[4] == '\x03':
      client_seed = tcp.server.data[5:37]
      client_iv = tcp.server.data[37:53]
      client_key = create_key(tcp.module_data['password'], client_seed)

      tcp.module_data['client_key'] = client_key
      tcp.module_data['client_iv'] = client_iv

      tcp.discard(tcp.server.count_new)
      chop.tsprnt('Client Key Generated')
      chop.tsprnt('')
      return

    elif not(tcp.module_data.has_key('client_key')):
      chop.tsprnt('Skipping')
      tcp.discard(tcp.server.count_new)
      return

    else:
      if (len_server == 1):
        decode_command('server', command_server, '', tcp.module_data['commands'])
        return

      tmp = decrypt(tcp.server.data[5:tcp.server.count_new], tcp.module_data['client_key'], tcp.module_data['client_iv'])
      decode_command('server', command_server, tmp, tcp.module_data['commands'])

      tcp.discard(tcp.server.count_new)
      return

  return


def shutdown(module_data):
    return


def taste(tcp):
    " Called when a new stream is detected after setup but before data is received"
    return True


def teardown(tcp):
    return


