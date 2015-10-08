#!/bin/python
# IDAPython script that can be used to identify dynamically loaded functions
# in TeslaCrypt samples leveraging the Carberp source code. 

apis = {
	"pFlushViewOfFile" : 0x664FD32B,
	"pLoadLibraryA" : 0xC8AC8026,
	"pLoadLibraryW" : 0xC8AC8030,
	"pLoadLibraryExA" : 0x20088E6A,
	"pLoadLibraryExW" : 0x20088E7C,
	"pFreeLibrary" : 0x4B935B8E,
	"pGetProcAddress" : 0x1FC0EAEE,
	"pTerminateProcess" : 0x9E6FA842,
	"pVirtualAlloc" : 0x697A6AFE,
	"pVirtualAllocEx" : 0x9ABFB8A6,
	"pVirtualFree" : 0x3A35705F,
	"pVirtualFreeEx" : 0x5C17EC75,
	"pVirtualQuery" : 0x6A582465,
	"pVirtualQueryEx" : 0x919786E,
	"pVirtualProtect" : 0xA9DE6F5A,
	"pVirtualProtectEx" : 0x9BD6888F,
	"pCloseHandle" : 0x723EB0D5,
	"pGlobalAlloc" : 0x725EA171,
	"pGlobalFree" : 0x240339C8,
	"pCreateFileA" : 0x8F8F114,
	"pCreateFileW" : 0x8F8F102,
	"pWriteFile" : 0xF3FD1C3,
	"pGetCurrentDirectoryA" : 0xC80715CE,
	"pWriteProcessMemory" : 0xBEA0BF35,
	"pCreateRemoteThread" : 0xE61874B3,
	"pReadFile" : 0x487FE16B,
	"pSetFilePointer" : 0xEF48E03A,
	"pCopyFileA" : 0x2EE4F10D,
	"pCopyFileW" : 0x2EE4F11B,
	"pMoveFileA" : 0x20E4E9ED,
	"pMoveFileW" : 0x20E4E9FB,
	"pMoveFileExA" : 0x3A7A7478,
	"pMoveFileExW" : 0x3A7A746E,
	"pDeleteFileA" : 0x81F0F0DF,
	"pDeleteFileW" : 0x81F0F0C9,
	"pGetFileSize" : 0xAEF7CBF1,
	"pCreateFileMappingA" : 0xEF0A25B7,
	"pCreateFileMappingW" : 0xEF0A25A1,
	"pMapViewOfFile" : 0x5CD9430,
	"pGetFileTime" : 0xAE17C071,
	"pSetFileTime" : 0xAE17C571,
	"pGetModuleHandleA" : 0xA48D6762,
	"pGetModuleHandleW" : 0xA48D6774,
	"pUnmapViewOfFile" : 0x77CD9567,
	"pWaitForSingleObject" : 0xC54374F3,
	"pSleep" : 0x3D9972F5,
	"pWideCharToMultiByte" : 0xE74F57EE,
	"pMultiByteToWideChar" : 0x5AA7E70B,
	"pGetModuleFileNameA" : 0x774393E8,
	"pGetModuleFileNameW" : 0x774393FE,
	"pGetSystemDirectoryA" : 0x49A1374A,
	"pGetSystemDirectoryW" : 0x49A1375C,
	"pGetTempPathA" : 0x58FE7ABE,
	"pGetTempPathW" : 0x58FE7AA8,
	"pGetVolumeInformationA" : 0x67ECDE97,
	"pGetVolumeInformationW" : 0x67ECDE81,
	"pSetFileAttributesA" : 0x4D5587B7,
	"pSetFileAttributesW" : 0x4D5587A1,
	"pCreateProcessA" : 0x46318AC7,
	"pCreateProcessW" : 0x46318AD1,
	"pGetVersionExA" : 0x9C480E24,
	"pGetVersionExW" : 0x9C480E32,
	"pCreateThread" : 0x6FB89AF0,
	"pCreateMutexA" : 0xBF78969C,
	"pCreateMutexW" : 0xBF78968A,
	"pReleaseMutex" : 0xBB74A4A2,
	"pGetVersion" : 0xCB932CE2,
	"pDeviceIoControl" : 0x82E8173,
	"pQueryDosDeviceA" : 0xAC81BECB,
	"pQueryDosDeviceW" : 0xAC81BEDD,
	"pIsBadReadPtr" : 0x7D544DBD,
	"pIsBadWritePtr" : 0xAC85818D,
	"pGetCurrentProcess" : 0xD89AD05,
	"pCreateEventW" : 0x8D5A50CA,
	"pSetEvent" : 0x5E7EE0D0,
	"pResetEvent" : 0x3B3EE0F9,
	"pGetShortPathNameA" : 0x223296ED,
	"pGetShortPathNameW" : 0x223296FB,
	"pLocalFree" : 0x84033DEB,
	"pGetPrivateProfileStringA" : 0xAA19E291,
	"pGetPrivateProfileStringW" : 0xAA19E287,
	"pGetFileAttributesA" : 0x475587B7,
	"pGetFileAttributesW" : 0x475587A1,
	"pGetEnvironmentVariableA" : 0x9802EF30,
	"pGetEnvironmentVariableW" : 0x9802EF26,
	"pReadProcessMemory" : 0x9D00A761,
	"pExitProcess" : 0x95902B19,
	"pOpenProcess" : 0x99A4299D,
	"pGetCurrentProcessId" : 0x6B416786,
	"pProcess32First" : 0x19F78C90,
	"pProcess32Next" : 0xC930EA1E,
	"pCreateToolhelp32Snapshot" : 0x5BC1D14F,
	"pWinExec" : 0xE8BF6DAD,
	"pFindResourceA" : 0x8FE060C,
	"pSetLastError" : 0x1295012C,
	"pLoadResource" : 0x1A10BD8B,
	"pLockResource" : 0x1510BD8A,
	"pSizeofResource" : 0x86867F0E,
	"pLockRsrc" : 0xBAC5467D,
	"pGetTempFileNameA" : 0xFA4F502,
	"pGetTempFileNameW" : 0xFA4F514,
	"pGetLongPathNameA" : 0x9835D5A1,
	"pCreateEventA" : 0x8D5A50DC,
	"pConnectNamedPipe" : 0x7235F00E,
	"pCreateNamedPipeA" : 0x42F9BB48,
	"pGetTickCount" : 0x69260152,
	"pExitThread" : 0x768AA260,
	"plstrcmpiA" : 0x515BE757,
	"pSuspendThread" : 0xEEBA5EBA,
	"pGetComputerNameA" : 0x3DEF91BA,
	"pGetThreadContext" : 0xAA1DE02F,
	"pSetThreadContext" : 0xAA1DC82F,
	"pResumeThread" : 0x7B88BF3B,
	"pProcessIdToSessionId" : 0x654F3F9E,
	"pWTSGetActiveConsoleSessionId" : 0x654FEEAC,
	"pOpenMutexA" : 0xAE52C609,
	"pCreateProcessInternalA" : 0xE24394E4,
	"pCreateProcessInternalW" : 0xE24394F2,
	"pTerminateThread" : 0xC09D5D66,
	"plopen" : 0xCDFC3010,
	"plstrcmpA" : 0x2CA2B7E6,
	"plstrcmpW" : 0x2CA2B7F0,
	"plstrcatA" : 0x2CA1B5E6,
	"plstrcatW" : 0x2CA1B5F0,
	"plstrcpyA" : 0x2CA5F366,
	"plstrcpyW" : 0x2CA5F370,
	"plstrlenA" : 0x2D40B8E6,
	"plstrlenW" : 0x2D40B8F0,
	"pThread32First" : 0x89B968D2,
	"pThread32Next" : 0x4C1077D6,
	"pOpenThread" : 0x7E92CA65,
	"pGetWindowsDirectoryA" : 0x78B00C7E,
	"pGetWindowsDirectoryW" : 0x78B00C68,
	"pFindFirstFileA" : 0x32432444,
	"pFindFirstFileW" : 0x32432452,
	"pFindNextFileA" : 0x279DEAD7,
	"pFindNextFileW" : 0x279DEAC1,
	"pFindClose" : 0x7B4842C1,
	"pRemoveDirectoryA" : 0x4AE7572B,
	"pInitializeCriticalSection" : 0xDA81BC58,
	"pEnterCriticalSection" : 0xF3B84F05,
	"pLeaveCriticalSection" : 0x392B6027,
	"pDeleteCriticalSection" : 0x7B2D2505,
	"pGetProcessHeap" : 0x68807354,
	"pHeapAlloc" : 0x5550B067,
	"pHeapReAlloc" : 0xFC7A6EFD,
	"pHeapSize" : 0x0AEBEA6A,
	"pHeapFree" : 0x084D25EA,
	"pGetCurrentThreadId" : 0xA45B370A,
	"pGetCurrentThread" : 0x4FBA916C,
	"pGlobalLock" : 0x25447AC6,
	"pGlobalUnlock" : 0xF50B872,
	"pSetErrorMode" : 0x6C544060,
	"pGetFileInformationByHandle" : 0xF149BCC4,
	"pFileTimeToLocalFileTime" : 0xE5792E94,
	"pFileTimeToDosDateTime" : 0xB68EBEF8,
	"pOutputDebugStringA" : 0xD0498CD4,
	"pExpandEnvironmentStringsA" : 0x23EBE98B,
	"pExpandEnvironmentStringsW" : 0x23EBE99D,
	"pOutputDebugStringW" : 0xD0498CC2,
	"pLocalAlloc" : 0x725CB0A1,
	"pFindFirstChangeNotificationA" : 0xE8402F0,
	"pFindCloseChangeNotification" : 0x3634D801,
	"pFindNextChangeNotification" : 0xFAB3FE71,
	"pCreateDirectoryW" : 0xA073561,
	"pCreateDirectoryA" : 0xA073577,
	"pOpenEventW" : 0x9C70005F,
	"pGetSystemTimeAsFileTime" : 0x6951E92A,
	"pGetSystemTime" : 0x270118E2,
	"pGetLogicalDriveStringsA" : 0x70F6FE31,
	"pGetDriveTypeA" : 0x399354CE,
	"pGetACP" : 0x5e9063ee,
	"pSetCurrentDirectoryW" : 0xc8071758,
	"pSetCurrentDirectoryA" : 0xc807174e,
	"pDuplicateHandle" : 0x533d3b41,
	"pGetExitCodeProcess" : 0xFDC94385,
	"pGetCommandLineA" : 0xFB0730C,
	"pCreateProcessAsUserA" : 0x985267C4,
	"pSetThreadToken" : 0xA16FE0FD,
	"pOpenProcessToken" : 0x80DBBE07,
	"pLookupPrivilegeValueA" : 0x1B3D12B9,
	"pLookupPrivilegeValueW" : 0x1B3D12AF,
	"pAdjustTokenPrivileges" : 0x7A2167DC,
	"pRegOpenKeyExA" : 0xAAD67FF8,
	"pRegOpenKeyExW" : 0xAAD67FEE,
	"pRegQueryInfoKeyA" : 0xBDF4DB19,
	"pRegQueryInfoKeyW" : 0xBDF4DB0F,
	"pRegEnumKeyExA" : 0xB4F673FD,
	"pRegEnumKeyExW" : 0xB4F673EB,
	"pRegEnumValueA" : 0xF65A7D95,
	"pRegEnumValueW" : 0xF65A7D83,
	"pRegQueryValueExA" : 0x1802E7C8,
	"pRegQueryValueExW" : 0x1802E7DE,
	"pRegCloseKey" : 0xDB355534,
	"pRegDeleteKeyA" : 0x398C5285,
	"pRegDeleteKeyW" : 0x398C5293,
	"pRegSetValueExA" : 0x3E400FD6,
	"pRegSetValueExW" : 0x3E400FC0,
	"pGetUserNameA" : 0xB9D41C2F,
	"pGetUserNameW" : 0xB9D41C39,
	"pOpenServiceA" : 0x83969964,
	"pStartServiceA" : 0x1CA1FD2F,
	"pControlService" : 0x5FFEE3F1,
	"pGetKernelObjectSecurity" : 0xB29136DD,
	"pOpenSCManagerA" : 0xA06E459C,
	"pQueryServiceStatusEx" : 0xF6C712F4,
	"pGetCurrentHwProfileA" : 0xF684C7A9,
	"pGetTokenInformation" : 0xD4ECC759,
	"pInitializeSecurityDescriptor" : 0xB8538A52,
	"pSetSecurityDescriptorOwner" : 0xDADD5994,
	"pSetFileSecurityW" : 0x5A9B2FDD,
	"pRegCreateKeyW" : 0xAE9E4290,
	"pRegCreateKeyA" : 0xAE9E4286,
	"pRegCreateKeyExW" : 0x90A097F0,
	"pRegCreateKeyExA" : 0x90A097E6,
	"pCloseServiceHandle" : 0x78CEC357,
	"pCryptAcquireContextA" : 0x8AD7DE34,
	"pCryptReleaseContext" : 0x72760BB8,
	"pCryptImportKey" : 0x78660DBE,
	"pCryptEncrypt" : 0xCEBF13BE,
	"pCryptDecrypt" : 0xCEBF17E6,
	"pCryptSetKeyParam" : 0x37A53419,
	"pCryptDestroyKey" : 0xD4B3D42,
	"pAllocateAndInitializeSid" : 0x28E9E291,
	"pCheckTokenMembership" : 0x87FEDB50,
	"pFreeSid" : 0x5CB5EF72,
	"pRegDeleteValueA" : 0x560c7c4a,
	"pExitWindowsEx" : 0xAD7043A4,
	"pPeekMessageW" : 0xD7A87C3A,
	"pDispatchMessageW" : 0x4BAED1DE,
	"pMsgWaitForMultipleObjects" : 0xD36CEAF0,
	"pWaitForInputIdle" : 0x4FAC81B4,
	"pGetWindowThreadProcessId" : 0x6C7F716F,
	"pFindWindowA" : 0x252B53B,
	"pGetSystemMetrics" : 0x8EBEF5B1,
	"pGetActiveWindow" : 0xDB7C98AC,
	"pGetKeyboardLayoutNameA" : 0xEA0FAD78,
	"pOpenClipboard" : 0x6ADFC795,
	"pGetClipboardData" : 0x8E7AE818,
	"pCloseClipboard" : 0xF0EC2212,
	"pGetWindowTextA" : 0x9C29100A,
	"pGetWindowTextW" : 0x9C29101C,
	"pGetForegroundWindow" : 0xCACD450,
	"pGetWindowLongPtrA" : 0x1D6C998B,
	"pGetWindowLongPtrW" : 0x1D6C999D,
	"pEnumChildWindows" : 0xAE8A5532,
	"pGetParent" : 0x5992A5F2,
	"pGetDesktopWindow" : 0xCD4AC62B,
	"pIsWindowVisible" : 0xCFAAD7BF,
	"pSetWindowLongA" : 0xBD6C998B,
	"pSetWindowLongW" : 0xBD6C999D,
	"pGetWindowLongA" : 0x1D6C998B,
	"pGetWindowLongW" : 0x1D6C999D,
	"pSetLayeredWindowAttributes" : 0x2DDBD2AF,
	"pSetWindowPos" : 0xA92DF5AF,
	"pMessageBoxA" : 0xABBC680D,
	"pMessageBoxW" : 0xABBC681B,
	"pGetClassNameW" : 0x484006A,
	"pGetClassNameA" : 0x484007C,
	"pShowWindow" : 0x7506E960,
	"pSendMessageW" : 0x58A81C3F,
	"pSendMessageA" : 0x58A81C29,
	"pEnumWindows" : 0x9940B5CA,
	"pIsWindow" : 0x9D4AF949,
	"pGetWindow" : 0xDA12E549,
	"pCreateDesktopW" : 0xC43ED7B1,
	"pCreateDesktopA" : 0xC43ED7A7,
	"pGetThreadDesktop" : 0x79F9B7FA,
	"pSwitchDesktop" : 0x5B92DEA5,
	"pSetThreadDesktop" : 0x79F99FFA,
	"pGetTopWindow" : 0xC90E0C33,
	"pMoveWindow" : 0x7234A16F,
	"pFindWindowExA" : 0xAD4FFCD5,
	"pGetMessageA" : 0xC8A274AC,
	"pSendMessageTimeoutW" : 0x65846C69,
	"pSendMessageTimeoutA" : 0x65846C7F,
	"pSetClipboardViewer" : 0x322391FC,
	"pIsClipboardFormatAvailable" : 0xB161BF96,
	"pChangeClipboardChain" : 0x7CF84417,
	"pPostMessageA" : 0xC8A87EA7,
	"pGetMessagePos" : 0x9D2F45DB,
	"pClientToScreen" : 0x543DF505,
	"pGetWindowRect" : 0x97F85FA0,
	"pDefWindowProcA" : 0xC6CE9B8A,
	"pCallWindowProcA" : 0xEE5FDA87,
	"pGetKeyNameTextW" : 0xAD34F519,
	"pGetKeyboardState" : 0xF5E780A6,
	"pGetKeyboardLayout" : 0xA0C69BF7,
	"pToUnicodeEx" : 0x2944D0D1,
	"pLoadCursorW" : 0xCFB2E5CF,
	"pRegisterClassA" : 0xAEABC9A4,
	"pCreateWindowExA" : 0xBF7EFB5A,
	"pTranslateMessage" : 0xC45D9631,
	"pDispatchMessageA" : 0x4BAED1C8,
	"pGetWindowDC" : 0xB95254C7,
	"pReleaseDC" : 0x4CB2D16D,
	"pFillRect" : 0xCAD4D692,
	"pActivateKeyboardLayout" : 0xD9EE8729,
	"pwvsprintfA" : 0x6B3AF0EC,
	"pwvsprintfW" : 0x6b3af0fa,
	"pWSACleanup" : 0x8FB8B5BD,
	"pWSAStartup" : 0xCDDE757D,
	"psocket" : 0xFC7AF16A,
	"pclosesocket" : 0x939D7D9C,
	"paccept" : 0x3C797B7A,
	"pbind" : 0xC5A7764,
	"phtons" : 0x8E9BF775,
	"plisten" : 0x9E7D3188,
	"precv" : 0xE5971F6,
	"psend" : 0xE797764,
	"pconnect" : 0xEDD8FE8A,
	"pshutdown" : 0x4C7C5841,
	"pgethostbyname" : 0xF44318C6,
	"pgethostbyaddr" : 0xF5A25C51,
	"pinet_addr" : 0x95E4A5D7,
	"pinet_ntoa" : 0x9400A044,
	"pgetaddrinfo" : 0xD9F839BA,
	"pgetpeername" : 0xD939F838,
	"pselect" : 0x5D99726A,
	"psetsockopt" : 0xD8923733,
	"pWSAGetLastError" : 0x8E878072,
	"pWSASetLastError" : 0x8E850072,
	"pRtlComputeCrc32" : 0x687B7023,
	"pRtlImageDirectoryEntryToData" : 0x503f7b28,
	"pRtlInitUnicodeString" : 0x3287EC73,
	"pRtlInitAnsiString" : 0xEE02056A,
	"pNtOpenFile" : 0x9C45B56C,
	"pNtOpenDirectoryObject" : 0xF5F11CF0,
	"pNtCreateSection" : 0x6E6F608B,
	"pNtOpenSection" : 0x5FA9AB38,
	"pZwLoadDriver" : 0x42F57D33,
	"pZwUnloadDriver" : 0x95849B61,
	"pRtlAdjustPrivilege" : 0xC2A6B1AE,
	"pZwMakeTemporaryObject" : 0x128CE9D3,
	"pNtClose" : 0x3D9AC241,
	"pRtlImageNtHeader" : 0xDD39FD14,
	"pZwQuerySystemInformation" : 0xBC44A131,
	"pZwUnmapViewOfSection" : 0x9ED4D161,
	"pZwMapViewOfSection" : 0x594D9A3C,
	"pZwQueueApcThread" : 0xC0E4F6EE,
	"pZwResumeThread" : 0xACF8BF39,
	"pZwTestAlert" : 0xC952A06B,
	"pZwQueryInformationThread" : 0xFAEDF3AA,
	"pZwOpenProcess" : 0x9C0AC99D,
	"pZwOpenProcessToken" : 0xADACBE07,
	"pZwClose" : 0x3D9A9259,
	"pZwAllocateVirtualMemory" : 0x594AA9E4,
	"pZwFreeVirtualMemory" : 0xBED3922C,
	"pZwWriteVirtualMemory" : 0xEEE7AF23,
	"pZwProtectVirtualMemory" : 0x3836C63E,
	"pRtlCreateUserThread" : 0xE9E0A4F7,
	"pLdrLoadDll" : 0x78740534,
	"pLdrGetDllHandle" : 0x7E287C6A,
	"pLdrGetProcedureAddress" : 0x323C2875,
	"pZwSetContextThread" : 0x62E2FE6F,
	"pZwSetInformationProcess" : 0xCA2BF652,
	"pZwQueryInformationProcess" : 0xA638CE5F,
	"pZwQueryInformationFile" : 0x0f7ba4b7,
	"pZwShutdownSystem" : 0x6F1C809E,
	"pWinStationTerminateProcess" : 0xA60C5F05,
	"pSHGetSpecialFolderPathA" : 0xC95D8550,
	"pSHGetSpecialFolderPathW" : 0xC95D8546,
	"pFindExecutableA" : 0x37707500,
	"pFindExecutableW" : 0x37707516,
	"pSHGetFolderPathA" : 0xDEAA9541,
	"pSHGetFolderPathW" : 0xDEAA9557,
	"pShellExecuteW" : 0x570BC88F,
	"pShellExecuteA" : 0x570BC899,
	"pStrStrIW" : 0x3E3B7742,
	"pStrStrIA" : 0x3E3B7754,
	"pShellExecuteExA" : 0xf2276983,
	"pShellExecuteExW" : 0xf2276995,
	"pInternetConnectA" : 0xBE618D3E,
	"pInternetConnectW" : 0xBE618D28,
	"pHttpOpenRequestA" : 0x1510002F,
	"pHttpOpenRequestW" : 0x15100039,
	"pHttpSendRequestA" : 0x9F13856A,
	"pHttpSendRequestW" : 0x9F13857C,
	"pInternetCloseHandle" : 0x7314FB0C,
	"pInternetQueryOptionA" : 0x2AE71934,
	"pInternetQueryOptionW" : 0x2AE71922,
	"pInternetSetOptionA" : 0x1AD09C78,
	"pInternetSetStatusCallback" : 0x9EF6461,
	"pHttpQueryInfoA" : 0x2F5CE027,
	"pHttpQueryInfoW" : 0x2F5CE031,
	"pHttpAddRequestHeadersA" : 0xB5901061,
	"pHttpAddRequestHeadersW" : 0xB5901077,
	"pGetUrlCacheEntryInfoW" : 0x57FBC0CB,
	"pFindFirstUrlCacheEntryA" : 0xDDCB15D,
	"pFindNextUrlCacheEntryA" : 0x8733D614,
	"pDeleteUrlCacheEntry" : 0xA3A80AB6,
	"pFindCloseUrlCache" : 0xFDE87743,
	"pInternetOpenA" : 0x8593DD7,
	"pInternetOpenUrlA" : 0xB87DBD66,
	"pInternetReadFile" : 0x1A212962,
	"pInternetReadFileExA" : 0x2C523864,
	"pInternetReadFileExW" : 0x2C523872,
	"pReadUrlCacheEntryStream" : 0x1672BC16,
	"pUnlockUrlCacheEntryStream" : 0xEE22C82A,
	"pRetrieveUrlCacheEntryStreamA" : 0x609C6936,
	"pFindFirstUrlCacheEntryExA" : 0x2C567F36,
	"pFindNextUrlCacheEntryExA" : 0xF5841D8D,
	"pDeleteUrlCacheEntryA" : 0xD4055B10,
	"pURLDownloadToFileA" : 0xD95D2399,
	"pURLDownloadToFileW" : 0xD95D238F,
	"pObtainUserAgentString" : 0x534D481,
	"pCreateCompatibleBitmap" : 0x6B3470D5,
	"pCreateCompatibleDC" : 0x5AF0017C,
	"pSelectObject" : 0x4894DAFC,
	"pBitBlt" : 0x9E90B462,
	"pDeleteDC" : 0x5E10F525,
	"pDeleteObject" : 0x48B87EFC,
	"pGetDeviceCaps" : 0x39E9624F,
	"pCreateSolidBrush" : 0xEF9AC06E,
	"pEnableEUDC" : 0xB676E907,
	"pGdiplusStartup" : 0x55F74962,
	"pGdipCreateBitmapFromHBITMAP" : 0xB7F0B572,
	"pGdipSaveImageToFile" : 0xE410B3EB,
	"pGdipDisposeImage" : 0x226FA923,
	"pGdiplusShutdown" : 0x99A24264,
	"pCertOpenSystemStoreA" : 0xEEA9ED9D,
	"pCertEnumCertificatesInStore" : 0x9897E094,
	"pPFXExportCertStoreEx" : 0xDFDB467E,
	"pCertCloseStore" : 0xCC1A6B6B,
	"pPFXImportCertStore" : 0x3A1B7F5D,
	"pCertAddCertificateContextToStore" : 0xDC6DD6E5,
	"pCertDuplicateCertificateContext" : 0x2F16F47,
	"pCertDeleteCertificateFromStore" : 0x5B08B5F,
	"pCheckSumMappedFile" : 0xd5edc5a2,
	"pPathCombineA" : 0x45b615d5,
	"pPathCombineW" : 0x45b615c3,
	"pPathFindFileNameA" : 0xeed5398c,
	"pPathFindFileNameW" : 0xEED5399A,
	"pGetProcessImageFileNameA" : 0x2741105,
	"pCoInitializeEx" : 0x7573DE28,
	"pCoUninitialize" : 0xEDB3159D,
	"pCoCreateInstance" : 0x368435BE,
	"pCoInitializeSecurity" : 0x910EACB3,
	"pAddPrintProvidorA" : 0x4B12B4DF,
	"pDeletePrintProvidorA" : 0x3D369C42
}

# Attempt to create the 'carberpAPI' enumeration that will be used later on.
id_enum = idc.AddEnum(0, "carberpAPI", idaapi.hexflag());
if id_enum != 0xffffffff:
	for k,v in apis.iteritems():
		idc.AddConstEx(id_enum, k, v, -1);
	print "[*] Added Carberp API enumeration: carberpAPI"


def get_all_enum_constants():
	'''
	Returns hash of constant numerical representations. Value of each key is an 
	array containing the constant name (array[0]) and the constant ID (array[1]).
	'''
	constants = {}
	all_enums = GetEnumQty()
	for i in range(0, all_enums):
		en = GetnEnum(i)
		first = GetFirstConst(en, -1)
		v1 = GetConstEx(en, first, 0, -1)
		name = GetConstName(v1)
		constants[int(first)] = [name, en]
		while True:
			first = GetNextConst(en, first, -1)
			v1 = GetConstEx(en, first, 0, -1)
			name = GetConstName(v1)
			if first == 0xFFFFFFFF:
				break
			constants[int(first)] = [name, en]
	return constants


# Grabbing all enumerations in the IDB and storing to a variable for later use.
ALL_CONSTANTS = get_all_enum_constants()


def modify_push_to_enum(addr, constants):
	'''
	Convert address to enumeration
	'''
	constant_id = GetOperandValue(addr, 0)
	if constant_id in constants:	
		enum_id = constants[constant_id]
		OpEnumEx(addr, 0, enum_id[1], 0)
		return enum_id[0]
	else:
		return None


def enum_for_xrefs(f_addr, stack_pos):
	'''
	This function will search for cross-references to a given function. 
	'''
	for x in XrefsTo(f_addr, flags=0):
		curr_addr = x.frm
		print '[+] Cross-reference discovered at 0x%x' % curr_addr
		addr_m_30 = curr_addr-30

		current_constant = None
		c = 0
		while curr_addr >= addr_m_30:
			curr_addr = PrevHead(curr_addr)
			if GetMnem(curr_addr) == "push":
				c += 1
				if c == stack_pos:
					data = GetOperandValue(curr_addr, 0)
					if data > 0xFFFF and data < 0xFFFFFFFF:
						print '[*] Enumeration found: 0x%x' % data
						enum = modify_push_to_enum(curr_addr, ALL_CONSTANTS)
	return None


def find_pattern(pattern, max_attempt=5):
	'''
	Find a pattern in a binary, and provide any references to said pattern.
	'''
	addr = MinEA()
	results = []
	for x in range(0, max_attempt):
		addr = idc.FindBinary(addr, SEARCH_DOWN, pattern)
		if addr != idc.BADADDR:
			if addr not in results:
				results.append(addr)
	return results


def find_next_call_address(ea, max_attempt=5):
	'''
	Attempt to find the next call instruction after a particular address.
	'''
	for x in range(0, max_attempt):
		if GetMnem(ea) == "call":
			return GetOperandValue(ea,0)
		ea = NextHead(ea)
	return None


def find_GetProcAddressEx():
	'''
	Try and find an instance of 'push C8AC8026'. This is a way of identifying
	the GetProcAddressEx() function within the binary.
	'''
	load_library = find_pattern('68 26 80 AC C8')
	if load_library:
		likely_function = find_next_call_address(load_library[0])
		print '[+] GetProcAddressEx discovered at 0x%x' % likely_function
		return likely_function
	return None


def find_GetApiAddr():
	'''
	Try and find an instance of 'push 1A212962'. This is a way of identifying
	the GetApiAddr() function within the binary.
	'''
	load_library = find_pattern('68 62 29 21 1A')
	if load_library:
		likely_function = find_next_call_address(load_library[0])
		print '[+] GetApiAddr discovered at 0x%x' % likely_function
		return likely_function
	return None
	

GetProcAddressEx = find_GetProcAddressEx()
if GetProcAddressEx:
	print "[+] Attempting to discover cross-references for GetProcAddressEx"
	enum_for_xrefs(GetProcAddressEx, 3)

GetApiAddr = find_GetApiAddr()
if GetApiAddr:
	print "[+] Attempting to discover cross-references for GetApiAddr"
	enum_for_xrefs(GetApiAddr, 2)