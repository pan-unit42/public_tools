begin_position = 0x100194D0 # This value must be changed
begin_position_copy = begin_position

def decrypt(data, key):
	out = ""
	c = 0
	for d in data:
		out += chr((c ^ key ^ ord(d)) & 0xFF)
		c+=1
	return out

def find_function_arg(addr):
	while True:
		addr = idc.PrevHead(addr)
		if GetMnem(addr) == "push":
			return GetOperandValue(addr, 0)

def get_string(position, length):
	c = 0
	out = ""
	while c < length:
		out += chr(Byte(position+c))
		c+=1
	return out

all_decrypted = []
while Word(begin_position) != 0:
	key = Word(begin_position)
	MakeWord(begin_position)
	MakeComm(begin_position, "")
	begin_position += 2
	data_len = Word(begin_position)
	MakeWord(begin_position)
	MakeComm(begin_position, "")
	begin_position += 2
	MakeDword(begin_position)
	data = get_string(Dword(begin_position), data_len)
	decrypted = decrypt(data, key)
	MakeComm(begin_position, decrypted)
	print "[0x%x] [%d] Decrypted: %s" % (begin_position, len(all_decrypted), repr(decrypted))
	begin_position += 4
	all_decrypted.append(decrypted)

for addr in XrefsTo(begin_position_copy, flags=0):
	sub_addr = idaapi.get_func(addr.frm).startEA
	for s_addr in XrefsTo(sub_addr, flags=0):
		arg = find_function_arg(s_addr.frm)
		MakeComm(s_addr.frm, all_decrypted[arg])