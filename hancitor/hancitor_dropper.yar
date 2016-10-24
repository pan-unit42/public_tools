rule h_dropper : vb_win32api
{
	meta:
		author = "Jeff White - jwhite@paloaltonetworks.com @noottrak"
		date   = "20OCT2016"
		hash1  = "03aef51be133425a0e5978ab2529890854ecf1b98a7cf8289c142a62de7acd1a"
		hash2  = "4b3912077ef47515b2b74bc1f39de44ddd683a3a79f45c93777e49245f0e9848"
		hash3  = "a78972ac6dee8c7292ae06783cfa1f918bacfe956595d30a0a8d99858ce94b5a"
		hash4  = "b586c11f5485e3a38a156cba10379a4135a8fe34aa2798af8d543c059f0ac9a4"
		hash5  = "23fe2647f544fad876121e1fabe5a702282ae59ac9a1a92dccf93e804bb78f77"
		hash6  = "16aec80227bdce01ed6cafffd723f59f46bbb4e7ab8a7de707501d8ad08ac6aa"
		hash7  = "3274e2b7228ebd57205da16bb9798fa75439869dad2da4506dbad6150a4f06a2"
		hash8  = "14211739584aa0f04ba8845a9b66434529e5e4636f460d34fa84821ebfb142fd"
		hash9  = "b506faff00ae557056d387442e9d4d2a53e87c5f9cd59f75db9ba5525ffa0ba3"
		description = "Detects Microsoft Word documents using a technique commonly found to deploy Hancitor or H1N1 downloaders"
		
	strings:
		$api_virtualalloc       = { 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 [0-2] 00 } 			// VirtualAlloc??
		$api_heapalloc          = { 00 48 65 61 70 41 6C 6C 6F 63 00 } 					// HeapAlloc
		$api_rtlmovememory      = { 00 52 74 6C 4D 6F 76 65 4D 65 6D 6F 72 79 00 }			// RtlMoveMemory
		$api_callwindowproc     = { 00 43 61 6C 6C 57 69 6E 64 6F 77 50 72 6F 63 [0-1] 00 }		// CallWindowProc?
		$api_enumresourcetypes  = { 00 45 6E 75 6D 52 65 73 6F 75 72 63 65 54 79 70 65 73 [0-1] 00 }	// EnumResourceTypes?
		$api_enumsystemlanguagegroups = { 00 45 6E 75 6D 53 79 73 74 65 6D 4C 61 6E 67 75 61 67 65 47 72 6F 75 70 73 [0-1] 00 } // EnumSystemLanguageGroups?
		$api_enumuilanguages    = { 00 45 6E 75 6D 55 49 4C 61 6E 67 75 61 67 65 73 [0-1] 00 }		// EnumUILanguages?
		$api_enumdateformats	= { 00 45 6E 75 6D 44 61 74 65 46 6F 72 6D 61 74 73 [0-1] 00 }		// EnumDateFormats?
		$magic_pola  		= { 50 4F 4C 41 }							// POLA
		$magic_starfall		= { 53 54 41 52 46 41 4C 4C }						// STARFALL

	condition:
		uint32be(0) == 0xD0CF11E0 and 3 of ($api_*) and 1 of ($magic_*) and filesize < 1MB
}
