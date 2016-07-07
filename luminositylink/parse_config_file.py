# Script to extract and parse a LuminosityLink sample's configuration. Unlikely
# to work on a sample that has been packed beyond the default ConfuserEx stuff
# that is written into the builder.
#
# Written by Josh Grunzweig

from Crypto.Cipher import AES
import base64
import hashlib
import sys, re, string, md5, csv

KNOWN_KEYS = [
	"\\ecnOnuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS",
	"This confi'g contains nothing useful. Quit acting as if you're cool by decrypting it.",
	"My.Resources.SMARTLOGS",
	"Specify a Password"
	]


def decrypt_data(data, key_string):
	decoded_data = base64.b64decode(data)
	m = hashlib.md5()
	m.update(key_string)
	md5 = m.digest()
	key = md5[0:15]+md5+"\x00"
	mode = AES.MODE_ECB
	iv = '\x00' * 16
	e = AES.new(key, mode, iv)
	return e.decrypt(decoded_data)


def sha256_file(fname):
	try:
		hash_sha256 = hashlib.sha256()
		with open(fname, "rb") as f:
			for chunk in iter(lambda: f.read(4096), b""):
				hash_sha256.update(chunk)
		return hash_sha256.hexdigest()
	except Exception as e:
		print e.message


def parse_settings(string):
	settings = {
		'i' : "Enable Client Installation/Startup",
		'd' : "Client Persistence Module: Protect Luminosity's Client Binary",
		's' : "Silent Mode (Hide Luminosity Window on Client PC)",
		'a' : "Proactive Anti-Malware: Clean Malicious Files and Speed up Client PC",
		'n' : "Power Saver: Prevent Sleep Mode and Turn off Monitor after 15 minutes of inactivity",
		'm' : "Remove File after Execution (Melt)",
		'v' : "Anti-Virtual Machines/Debugging",
		'h' : "Hide File and Directories",
		'b' : "Backup Startup"
	}
	results = []
	for char in string:
		if char in settings:
			results.append(settings[char])
	return results


def test_decrypted_data(data):
	if "RDP Wrapper Library configuration" not in data:
		if "<?xml version=" not in data:
			if len(data.split("|")) > 5:
				c = 0
				for x in data:
					if x not in string.printable: c+=1
				if c < 30:
					return True
	return False


def print_results(data):
	format_string = '''
SHA256:               {sha256}
Encryption Key:       {key}
Domain/IP:            {domain_ip}
Port:                 {port}
Backup DNS:           {backup_dns}
Filename:             {filename}
Startup Name:         {startup_name}
Folder Name:          {folder_name}
Data Directory Name:  {data_directory_name}
Backup Startup Exe:   {backup_startup_exe}
Mutex:                {mutex}
Build ID:             {build_id}
Settings:
  [{c1}] Enable Client Installation/Startup
  [{c2}] Client Persistence Module: Protect Luminosity's Client Binary
  [{c3}] Silent Mode (Hide Luminosity Window on Client PC)
  [{c4}] Proactive Anti-Malware: Clean Malicious Files and Speed up Client PC
  [{c5}] Power Saver: Prevent Sleep Mode and Turn off Monitor after 15 minutes of inactivity
  [{c6}] Remove File after Execution (Melt)
  [{c7}] Anti-Virtual Machines/Debugging
  [{c8}] Hide File and Directories
  [{c9}] Backup Startup
'''.format( 
	sha256 = data["sha256"],
	key = data["encryption_key"],
	domain_ip = data["domain_ip"],
	port = data["port"],
	backup_dns = data["backup_dns"],
	filename = data["filename"],
	startup_name = data["startup_name"],
	folder_name = data["folder_name"],
	data_directory_name = data["data_directory_name"],
	backup_startup_exe = data["backup_startup_exe"],
	mutex = data["mutex"],
	build_id = data["build_id"],
	c1 = "X" if "i" in data["settings"] else " ",
	c2 = "X" if "d" in data["settings"] else " ",
	c3 = "X" if "s" in data["settings"] else " ",
	c4 = "X" if "a" in data["settings"] else " ",
	c5 = "X" if "n" in data["settings"] else " ",
	c6 = "X" if "m" in data["settings"] else " ",
	c7 = "X" if "v" in data["settings"] else " ",
	c8 = "X" if "h" in data["settings"] else " ",
	c9 = "X" if "b" in data["settings"] else " ",
)
	print format_string


def feb_config(t, k, s):
	results = {}
	results["sha256"] = s
	results["domain_ip"] = t[0]
	results["port"] = t[1]
	results["backup_dns"] = t[2]
	results["filename"] = t[3]
	results["startup_name"] = t[4]
	results["folder_name"] = "N/A"
	results["data_directory_name"] = "N/A"
	results["backup_startup_exe"] =  "N/A"
	results["mutex"] = t[5]
	results["build_id"] = t[7]
	results["settings"] = t[6]
	results["encryption_key"] = k
	return results


def june_config(t, k, s):
	results = {}
	results["sha256"] = s
	results["domain_ip"] = t[0]
	results["port"] = t[1]
	backup_dns = t[2]
	if backup_dns == "D": backup_dns = "Disabled"
	results["backup_dns"] = backup_dns
	results["filename"] = t[3]
	results["startup_name"] = t[4]
	results["folder_name"] = t[5]
	results["data_directory_name"] = t[6]
	results["backup_startup_exe"] = t[7]
	results["mutex"] = t[8]
	results["build_id"] = t[9]
	results["settings"] = t[10]
	results["encryption_key"] = k
	return results 


def main():
	filename = sys.argv[1]

	f = open(filename, 'rb')
	fd = f.read()
	f.close()

	sha256 = sha256_file(filename)

	for data in re.findall("([ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\+\/\=]{50,})", fd):
		try:
			for k in KNOWN_KEYS:
				decrypted = decrypt_data(data, k)

				if test_decrypted_data(decrypted):
					t = decrypted.strip().split("|")
					if len(t) > 10:
						parsed_data = june_config(t, k, sha256)
					elif len(t) > 5:
						parsed_data = feb_config(t, k, sha256)
					print_results(parsed_data)
					sys.exit(0) # Got result, time to shut off

		except Exception as e:
			pass

if __name__ == "__main__":
	if len(sys.argv) != 2:
		print "Usage: python {} [LuminosityLink Sample]".format(__file__)
		sys.exit(1)
	main()

	
		