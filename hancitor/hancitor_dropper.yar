rule h_dropper : vb_win32api
{
    meta:
        author = "Jeff White - jwhite@paloaltonetworks.com @noottrak"
        date   = "25MAY2017"
        hash1  = "03aef51be133425a0e5978ab2529890854ecf1b98a7cf8289c142a62de7acd1a"
        hash2  = "4b3912077ef47515b2b74bc1f39de44ddd683a3a79f45c93777e49245f0e9848"
        hash3  = "a78972ac6dee8c7292ae06783cfa1f918bacfe956595d30a0a8d99858ce94b5a"
        hash4  = "b586c11f5485e3a38a156cba10379a4135a8fe34aa2798af8d543c059f0ac9a4"
        hash5  = "23fe2647f544fad876121e1fabe5a702282ae59ac9a1a92dccf93e804bb78f77"
        hash6  = "16aec80227bdce01ed6cafffd723f59f46bbb4e7ab8a7de707501d8ad08ac6aa"
        hash7  = "3274e2b7228ebd57205da16bb9798fa75439869dad2da4506dbad6150a4f06a2"
        hash8  = "14211739584aa0f04ba8845a9b66434529e5e4636f460d34fa84821ebfb142fd"
        hash9  = "b506faff00ae557056d387442e9d4d2a53e87c5f9cd59f75db9ba5525ffa0ba3"
        hash10 = "da7b5a206d29bd7ee6abac0431dcfa71e6abab22d63430bc495b62a6105d24e9"
        hash11 = "45289367ea1ddc0f33e77e2499fde0a3577a5137037f9208ed1cdded92ee2dc2"
        hash12 = "fc1f1845e47d4494a02407c524eb0e94b6484045adb783e90406367ae20a83ac"
        hash13 = "0f878f3d538e8c138959df81b344508054a2b3fd68102d619e3e914d81466e94"
        hash14 = "fc0b80006b33ec34f5214f2e88b8085cf0d2861c4492df52886fdcf2d9c62c48"
        hash15 = "05822b44dd03098ddfd568a51b729345e5e3c63e24df52054a7fc450711bf464"
        hash16 = "e1cb2bc858327f9967a3631056f7e513af17990d87780e4ee1c01bc141d3dc7f"
        hash17 = "c56ff7309ed75a4f416e6116f5a3777e15107811085ba96f7ca7f210d6780c14"
        hash18 = "7eaa732d95252bf05440aca56f1b2e789dab39af72031a11fc597be88b1ede7f"
        hash19 = "50e2d9ad219279f41ffc95b4a81eb20df5ab06059a0417cd4ca3bd892fde3549"
        hash20 = "5a3c843bfcf31c2f2f2a2e4d5f5967800a2474e07323e8baa46ff3ac64d60d4a"
        hash21 = "0b8f91277f2161875cfe2f49ef1e499bcb60d1caa677d7d2e96b71437c648e5d"
        hash22 = "d2d786e373e968858e8a45118b20b744c621e10c84d5bbfddd0ff12841c5442b"
        hash23 = "800bf028a23440134fc834efc5c1e02cc70f05b2e800bbc285d7c92a4b126b1c"
        hash24 = "35aa9a631a536ddce57ecf26e55c5c76d80fe91672bcdf60d0eddc1849d56012"
        hash25 = "7b8bd7b3aae87c57adbb8bdd2d2ce543a6db88f1fa9c0eefa65f4d8409884ffa"
        hash26 = "52eafd2cb49836ae64a5f16250e80aabdd40ffaf2f6b573ba745d30e6a1d2fa2"
        hash27 = "6a58cbbd0b5f47bd53c50260fdcd0a0e3b75b5109fa86278d961eb5d4e17fc13"
        hash28 = "fff786ec23e6385e1d4f06dcf6859cc2ce0a32cee46d8f2a0c8fd780b3ecf89a"
        hash29 = "8b46f9b12e93b64f4eb0aa392bc0d0c0a224e945fe8d3f4ebd9ad91e38e2b930"
        hash30 = "0980ff18bf4cf3b2892fa5fb1d8648e389f0e32bc4ac4c4f71727ba8fe535354"
        hash31 = "39cb85066f09ece243c60fd192877ef6fa1162ff0b83ac8bec16e6df495ee7af"
        hash32 = "895f520d46f62bfd262bf0881cfe56116c39506e01bb302230eb868247dbe50c"
        hash33 = "0cf705e4804f3585e44368e8d611ddb9376863ff8c4400d156d043f6b181924e"
        description = "Detects Microsoft Word documents using a technique commonly found to deploy Hancitor or H1N1 downloaders"
        
    strings:
        // Allocate memory
        $alloc_virtualalloc             = { 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 [0-2] 00 }                                       // VirtualAlloc??
        $alloc_heapalloc                = { 00 48 65 61 70 41 6C 6C 6F 63 00 }                                                      // HeapAlloc
        $alloc_allocatevirtualmemory    = { 00 [0-2] 41 6C 6C 6F 63 61 74 65 56 69 72 74 75 61 6C 4D 65 6D 6F 72 79 00 }            // ??AllocateVirtualMemory
        $alloc_heapcreate               = { 00 48 65 61 70 43 72 65 61 74 65 00 }                                                   // HeapCreate
        // Fill memory
        $mem_rtlmovememory              = { 00 52 74 6C 4D 6F 76 65 4D 65 6D 6F 72 79 00 }                                          // RtlMoveMemory
        $mem_writeprocessmemory         = { 00 57 72 69 74 65 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79 00 }                           // WriteProcessMemory
        $mem_writevirtualmemory         = { 00 [0-2] 57 72 69 74 65 56 69 72 74 75 61 6C 4D 65 6D 6F 72 79 00 }                     // ??WriteVirtualMemory
        // Call shellcode
        $api_callwindowproc             = { 00 43 61 6C 6C 57 69 6E 64 6F 77 50 72 6F 63 [0-1] 00 }                                 // CallWindowProc?
        $api_enumresourcetypes          = { 00 45 6E 75 6D 52 65 73 6F 75 72 63 65 54 79 70 65 73 [0-1] 00 }                        // EnumResourceTypes?
        $api_enumsystemlanguagegroups   = { 00 45 6E 75 6D 53 79 73 74 65 6D 4C 61 6E 67 75 61 67 65 47 72 6F 75 70 73 [0-1] 00 }   // EnumSystemLanguageGroups?
        $api_enumuilanguages            = { 00 45 6E 75 6D 55 49 4C 61 6E 67 75 61 67 65 73 [0-1] 00 }                              // EnumUILanguages?
        $api_enumdateformats            = { 00 45 6E 75 6D 44 61 74 65 46 6F 72 6D 61 74 73 [0-1] 00 }                              // EnumDateFormats?
        $api_enumcalendarinfo           = { 00 45 6E 75 6D 43 61 6C 65 6E 64 61 72 49 6E 66 6F [0-1] 00 }                           // EnumCalendarInfo?
        $api_enumtimeformats            = { 00 45 6E 75 6D 54 69 6D 65 46 6F 72 6D 61 74 73 57 [0-1] 00 }                           // EnumTimeFormats?
        $api_shccreatethread            = { 00 53 48 43 72 65 61 74 65 54 68 72 65 61 64 00 }                                       // SHCreateThread
        $api_graystring                 = { 00 47 72 61 79 53 74 72 69 6E 67 [0-1] 00 }                                             // GrayString?
        $api_createtimerqueuetimer      = { 00 43 72 65 61 74 65 54 69 6D 65 72 51 75 65 75 65 54 69 6D 65 72 00 }                  // CreateTimerQueueTimer

        // Magic headers
        $magic_pola                     = { 50 4F 4C 41 }                                                                           // POLA (also POLAROID)
        $magic_starfall                 = { 53 54 41 52 46 41 4C 4C }                                                               // STARFALL
        $magic_bullshit                 = { 42 55 4C 4C 53 48 49 54 }                                                               // BULLSHIT
        $magic_fortinet                 = { 46 4F 52 54 49 4E 45 54 }                                                               // FORTINET
        $magic_fortnnet                 = { 46 4F 52 54 4E 4E 45 54 }                                                               // FORTNNET
        $magic_trueform                 = { 54 52 55 45 46 4F 52 4D }                                                               // TRUEFORM
        $magic_deadface                 = { 44 45 41 44 46 41 43 45 }                                                               // DEADFACE
        $magic_nicework                 = { 4E 49 43 45 57 4F 52 4B }                                                               // NICEWORK
        $magic_murakami                 = { 4D 55 52 41 4B 41 4D 49 }                                                               // MURAKAMI
        $magic_fairgame                 = { 46 41 49 52 47 41 4D 45 }                                                               // FAIRGAME
        $magic_comodo                   = { 43 4F 4D 4F 44 4F }                                                                     // COMODO
        $magic_horror                   = { 48 4F 52 52 4F 52 }                                                                     // HORROR
        $magic_dreams                   = { 44 52 45 41 4D 53 }                                                                     // DREAMS
        $magic_at_abhie                 = { 40 41 42 48 49 45 }                                                                     // @ABHIE
        $magic_bang_abhie               = { 21 41 42 48 49 45 }                                                                     // !ABHIE
        $magic_theend                   = { 54 68 65 45 6E 64 }                                                                     // TheEnd
        $magic_bang_mizol               = { 21 4D 49 5A 4F 4C }                                                                     // !MIZOL
        $magic_bang_nicol               = { 21 4E 49 43 4F 4C }                                                                     // !NICOL
        $magic_bang_trust               = { 21 54 52 55 53 54 }                                                                     // !TRUST
        $magic_bang_nicht               = { 21 4E 49 43 48 54 }                                                                     // !NICHT
        $magic_bang_noise               = { 21 4E 4F 49 53 45 }                                                                     // !NOISE
        $magic_bang_drift               = { 21 44 52 49 46 54 }                                                                     // !DRIFT
        $magic_bang_tunes               = { 21 54 55 4E 45 53 }                                                                     // !TUNES
        $magic_bang_gnuss               = { 21 47 4E 55 53 53 }                                                                     // !GNUSS
        // Shellcode stub
        $stub_v1                        = { 49 45 4E 44 AE 42 60 82 [4-8] 08 00 }                                                   // Stub v1
        $stub_v2                        = { 01 01 06 3F 00 7F FF D9 [4-8] 08 00 }                                                   // Stub v2
    condition:
        uint32be(0) == 0xD0CF11E0 and filesize < 1MB and 1 of ($stub_*) and 1 of ($alloc_*) and 1 of ($mem_*) and 1 of ($api_*) and 1 of ($magic_*)
}
