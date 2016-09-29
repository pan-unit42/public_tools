rule h_dropper : vb_win32api
{
	meta:
		author = "Jeff White - jwhite@paloaltonetworks.com @noottrak"
		date   = "29SEP2016"
		hash1  = "03aef51be133425a0e5978ab2529890854ecf1b98a7cf8289c142a62de7acd1a"
		hash2  = "4b3912077ef47515b2b74bc1f39de44ddd683a3a79f45c93777e49245f0e9848"
		hash3  = "a78972ac6dee8c7292ae06783cfa1f918bacfe956595d30a0a8d99858ce94b5a"
		hash4  = "b586c11f5485e3a38a156cba10379a4135a8fe34aa2798af8d543c059f0ac9a4"
		hash5  = "23fe2647f544fad876121e1fabe5a702282ae59ac9a1a92dccf93e804bb78f77"
		hash6  = "16aec80227bdce01ed6cafffd723f59f46bbb4e7ab8a7de707501d8ad08ac6aa"
		description = "Detects Microsoft Word documents using a technique commonly found to deploy Hancitor or H1N1 downloaders"
		
	strings:
		$api_virtualalloc       = { 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 } 			// VirtualAlloc
		$api_heapalloc          = { 00 48 65 61 70 41 6C 6C 6F 63 00 } 					// HeapAlloc
		$api_rtlmovememory      = { 00 52 74 6C 4D 6F 76 65 4D 65 6D 6F 72 79 00 }			// RtlMoveMemory
		$api_callwindowproc     = { 00 43 61 6C 6C 57 69 6E 64 6F 77 50 72 6F 63 [0-1] 00 }		// CallWindowProc?
		$api_enumresourcetypes  = { 00 45 6E 75 6D 52 65 73 6F 75 72 63 65 54 79 70 65 73 [0-1] 00 }	// EnumResourceTypes?
		$api_enumsystemlanguagegroups = { 00 45 6E 75 6D 53 79 73 74 65 6D 4C 61 6E 67 75 61 67 65 47 72 6F 75 70 73 [0-1] 00 } // EnumSystemLanguageGroups?
		$magic  		= { 50 4F 4C 41 }							// POLA

	condition:
		uint32be(0) == 0xD0CF11E0 and 3 of ($api_*) and $magic and filesize < 1MB
}
