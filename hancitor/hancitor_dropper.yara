rule h_dropper : vb_win32api
{
	meta:
		author = "Jeff White - jwhite@paloaltonetworks.com @noottrak"
		date   = "11SEP2016"
		hash1  = "03aef51be133425a0e5978ab2529890854ecf1b98a7cf8289c142a62de7acd1a"
		hash2  = "4b3912077ef47515b2b74bc1f39de44ddd683a3a79f45c93777e49245f0e9848"
		hash3  = "a78972ac6dee8c7292ae06783cfa1f918bacfe956595d30a0a8d99858ce94b5a"
		hash4  = "b586c11f5485e3a38a156cba10379a4135a8fe34aa2798af8d543c059f0ac9a4"
		description = "Detects Microsoft Word documents using a technique commonly found to deploy Hancitor or H1N1 downloaders"
		
	strings:
		$api_01 = { 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 } 		// VirtualAlloc
		$api_02 = { 00 48 65 61 70 41 6C 6C 6F 63 00 } 				// HeapAlloc
		$api_03 = { 00 52 74 6C 4D 6F 76 65 4D 65 6D 6F 72 79 00 }		// RtlMoveMemory
		$api_04 = { 00 43 61 6C 6C 57 69 6E 64 6F 77 50 72 6F 63 41 00 }	// CallWindowProcAi
		$magic  = { 50 4F 4C 41 }						// POLA

	condition:
		uint32be(0) == 0xD0CF11E0 and 3 of ($api_*) and $magic
}
