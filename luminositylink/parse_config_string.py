# Script to parse a raw LuminosityLink configuration string.
# Written by Josh Grunzweig


from Crypto.Cipher import AES
import base64
import hashlib
import sys, re, string, md5, csv

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


def feb_config(t):
	results = {}
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
	return results


def june_config(t):
	results = {}
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
	return results 


def main():
	t = sys.argv[1].split("|")
	if len(t) > 10:
		parsed_data = june_config(t)
	elif len(t) > 5:
		parsed_data = feb_config(t)
	else:
		print "[-] Unable to identify proper LuminosityLink configuration string."
		sys.exit(1)
	print_results(parsed_data)

if __name__ == "__main__":
	if len(sys.argv) != 2:
		print "Usage: python {} [LuminosityLink Configuration String]".format(__file__)
		sys.exit(1)
	main()




	