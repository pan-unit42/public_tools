#!/usr/bin/env python3
import re, base64, zlib, binascii, argparse
from Crypto.Cipher import AES
from datetime import datetime


__author__ = "Jeff White [karttoon] @noottrak"
__email__ = "jwhite@paloaltonetworks.com"
__version__ = "1.0.0"
__date__ = "X"


# The garbageList is used to prevent loops for functions that don't replace content but simply append to existing
global garbageList
garbageList = list()


#####################
# Support Functions #
#####################


def stripASCII(contentData):
    """
    Strips out non-printable ASCII chars from strings, leaves CR/LF/Tab.

    Args:
        contentData: b"\x01He\x05\xFFllo"

    Returns:
        strippedMessage: "Hello"
    """
    strippedMessage = str()

    if type(contentData) == bytes:

        for entry in contentData:
            if (int(entry) == 9 or int(entry) == 10 or int(entry) == 13) or \
                (int(entry) >= 32 and int(entry) <= 126):
                strippedMessage += chr(int(entry))

    elif type(contentData) == str:

        for entry in contentData:
            if (ord(entry) == 9 or ord(entry) == 10 or ord(entry) == 13) or \
                (ord(entry) >= 32 and ord(entry) <= 126):
                strippedMessage += entry

    return strippedMessage.replace("\x00", "")


#######################
# Profiling Functions #
#######################


def scoreBehaviors(behaviorTags):
    """
    Scores the identified behaviors.

    Args:
        behaviorTags: ["Downloader", "Crypto"]

    Returns:
        score: 3.5
        verdict: "Likely Benign"
        behaviorData: ["Downloader - 1.5", "Crypto - 2.0"]
    """
    scoreValues = {

        # Negative
        # Behaviors which are generally only seen in Malware.
        "Code Injection": 10.0,
        "Key Logging": 3.0,
        "Screen Scraping": 2.0,
        "AppLocker Bypass": 2.0,
        "AMSI Bypass": 2.0,
        "Clear Logs": 2.0,
        "Coin Miner": 6.0,
        "Embedded File": 4.0,
        "Abnormal Size": 2.0,
        "Ransomware": 10.0,
        "DNS C2": 2.0,
        "Disabled Protections": 4.0,
        "Negative Context": 10.0,
        "Malicious Behavior Combo": 6.0,
        "Known Malware": 10.0,

        # Neutral
        # Behaviors which require more context to infer intent.
        "Downloader": 1.5,
        "Starts Process": 1.5,
        "Script Execution": 1.5,
        "Compression": 1.5,
        "Hidden Window": 0.5,
        "Custom Web Fields": 1.0,
        "Persistence": 1.0,
        "Sleeps": 0.5,
        "Uninstalls Apps": 0.5,
        "Obfuscation": 1.0,
        "Crypto": 2.0,
        "Enumeration": 0.5,
        "Registry": 0.5,
        "Sends Data": 1.0,
        "Byte Usage": 1.0,
        "SysInternals": 1.5,
        "One Liner": 2.0,
        "Variable Extension": 2.0,

        # Benign
        # Behaviors which are generally only seen in Benign scripts - subtracts from score.
        "Script Logging": -1.0,
        "License": -2.0,
        "Function Body": -2.0,
        "Positive Context": -3.0,
    }

    score = 0.0
    behaviorData = list()

    for behavior in behaviorTags:

        if "Known Malware:" in behavior:
            behaviorData.append("%s: %s - %s" % (behavior.split(":")[0], behavior.split(":")[1], scoreValues[behavior.split(":")[0]]))
            behavior = behavior.split(":")[0]
        elif "Obfuscation:" in behavior:
            behaviorData.append("%s: %s - %s" % (behavior.split(":")[0], behavior.split(":")[1], scoreValues[behavior.split(":")[0]]))
            behavior = behavior.split(":")[0]
        else:
            behaviorData.append("%s - %s" % (behavior, scoreValues[behavior]))

        score += scoreValues[behavior]

    if score < 0.0:
        score = 0.0

    # These verdicts are arbitrary and can be adjusted as necessary.
    if score == 0 and behaviorTags == []:
        verdict = "Unknown"
    elif score < 4:
        verdict = "Low Risk"
    elif 6 > score >= 4:
        verdict = "Mild Risk"
    elif 6 <= score <= 10:
        verdict = "Moderate Risk"
    elif 10 < score <= 20:
        verdict = "Elevated Risk"
    else:
        verdict = "Severe Risk"

    #verdict = "Unknown"

    return score, verdict, behaviorData


def profileBehaviors(behaviorTags, originalData, alternativeData, family):
    """
    Identifies the core behaviors for this profiling script. Broken into 3 sections for Malicious, Neutral, Benign.
    Includes meta-behaviors and keyword/combinations.

    Args:
        behaviorTags: []
        originalData: Original PowerShell Script
        alternativeData: Normalize/Unraveled PowerShell Script
        family: Identified Malware Family

    Returns:
        behaviorTags: ["Downloader", "Crypto"]
    """
    # {Behavior:[["entry1","entry2"],["entry3","entry4"]]}
    behaviorCol = {}

    #######################
    # Malicious Behaviors #
    #######################

    # Generates possible code injection variations.
    # Create memory
    c1 = ["VirtualAlloc", "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory", "HeapAlloc", "calloc"]
    # Move to memory
    c2 = ["RtlMoveMemory", "WriteProcessMemory", "memset", "Runtime.InteropServices.Marshal]::Copy",
          "Runtime.InteropServices.Marshal]::WriteByte"]
    # Execute in memory
    c3 = ["CallWindowProcA", "CallWindowProcW", "DialogBoxIndirectParamA", "DialogBoxIndirectParamW",
          "EnumCalendarInfoA", "EnumCalendarInfoW", "EnumDateFormatsA", "EnumDateFormatsW", "EnumDesktopWindows",
          "EnumDesktopsA", "EnumDesktopsW", "EnumLanguageGroupLocalesA", "EnumLanguageGroupLocalesW", "EnumPropsExA",
          "EnumPropsExW", "EnumPwrSchemes", "EnumResourceTypesA", "EnumResourceTypesW", "EnumResourceTypesExA",
          "EnumResourceTypesExW", "EnumSystemCodePagesA", "EnumSystemCodePagesW", "EnumSystemLanguageGroupsA",
          "EnumSystemLanguageGroupsW", "EnumSystemLocalesA", "EnumSystemLocalesW", "EnumThreadWindows",
          "EnumTimeFormatsA", "EnumTimeFormatsW", "EnumUILanguagesA", "EnumUILanguagesW", "EnumWindowStationsA",
          "EnumWindowStationsW", "EnumWindows", "EnumerateLoadedModules", "EnumerateLoadedModulesEx",
          "EnumerateLoadedModulesExW", "GrayStringA", "GrayStringW", "NotifyIpInterfaceChange",
          "NotifyTeredoPortChange", "NotifyUnicastIpAddressChange", "SHCreateThread", "SHCreateThreadWithHandle",
          "SendMessageCallbackA", "SendMessageCallbackW", "SetWinEventHook", "SetWindowsHookExA", "SetWindowsHookExW",
          "CreateThread", "Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer", "DeviceIoControl"]

    behaviorCol["Code Injection"] = [["Read", "Write", "Load", "Reflection.Assembly", "EntryPoint.Invoke"], ]

    behaviorCol["Key Logging"] = [
        ["GetAsyncKeyState", "Windows.Forms.Keys"],
        ["LShiftKey", "RShiftKey", "LControlKey", "RControlKey"],
    ]

    behaviorCol["Screen Scraping"] = [
        ["Drawing.Bitmap", "Width", "Height", "Screen"],
        ["Drawing.Graphics", "FromImage", "Screen"],
        ["CopyFromScreen", "Size"],
    ]

    behaviorCol["AppLocker Bypass"] = [
        ["regsvr32", "/i:http", "scrobj.dll"],
    ]

    behaviorCol["AMSI Bypass"] = [
        ["Management.Automation.AMSIUtils", "amsiInitFailed"],
        ["Expect100Continue"],
    ]

    behaviorCol["Clear Logs"] = [
        ["GlobalSession.ClearLog"],
        ["clear-eventlog", "Windows PowerShell"],
        ["clear-eventlog", "Applicatipn"],
        ["clear-eventlog", "System"],
        ["ClearMyTracksByProcess"],
    ]

    behaviorCol["Coin Miner"] = [
        ["miner_path", "miner_url"],
        ["minername", "Miner Path"],
        ["RainbowMiner"],
        ["Get-BestMiners"],
        ["xmrig.exe"],
    ]

    behaviorCol["Embedded File"] = [
        ["MZ", "This program cannot be run in DOS mode"],
        ["TVqQAAMAAAA"],  # B64 MZ Header
    ]

    behaviorCol["Abnormal Size"] = [  # Work done in processing.
    ]

    behaviorCol["Ransomware"] = [
        ["README-Encrypted-Files.html"],
        ["!!! Your Personal identification ID:"],
        ["DECRYPT_INSTRUCTIONS.html"],
        ["BinaryWriter", "Cryptography", "ReadWrite", "Add-Content", "html"],
    ]

    behaviorCol["DNS C2"] = [
        ["nslookup", "querytype=txt", "8.8.8.8"],
    ]

    behaviorCol["Disabled Protections"] = [
        ["REG_DWORD", "DisableAntiSpyware"],
        ["REG_DWORD", "DisableAntiVirus"],
        ["REG_DWORD", "DisableScanOnRealtimeEnable"],
        ["REG_DWORD", "DisableBlockAtFirstSeen"],
    ]

    behaviorCol["Negative Context"] = [
        ["Invoke-Shellcode"],  # Could be PowerSploit, Empire, or other frameworks.
        ["meterpreter"],
        ["metasploit"],
        ["HackerTools"],
        ["eval(function(p,a,c,k,e,d)"],  # Moved from obfuscation - unable to find benign usage.
        ["Download_Execute"],
        ["exetotext"],
        ["PostExploit"],
        ["PEBytes32", "PEBytes64"], # Could be Mimikatz or Empire.
        ["Invoke-Mypass"],
        ["PowerShell", "bypass", "hidden", "WebClient", "DownloadFile", "exe", "Start-Process", "APPDATA"],
        ["certutil.exe", "BEGIN CERTIFICATE"],  # "function set-Certificate()
        ["Invoke-BloodHound"], ["keylogging"],
        ["Auto-attack"],
        ["pastebin.com/raw/"],  # Common script downloading location.
        ["Shellcode", "payload"],
        ["$forward_port", "$forward_path", "$MyInvocation.MyCommand.Path", "${global:", "-Namespace Kernel32"],
        ["CurrentDomain.GetAssemblies()", "GetProcAddress').Invoke", "SetImplementationFlags"],
        ["return $Win32Types", "return $Win32Constants"],
        ["Get-Random -count 16", "Win32_NetworkAdapterConfiguration", "whoami", "POST"],
        ["Get-Random -Minimum", "System.Buffer]::BlockCopy", "GetResponseStream()", "POST"],
        ["*.vbs", "*.lnk", "DllOpen", "DllCall"],
        ["start-process  -WindowStyle hidden -FilePath taskkill.exe -ArgumentList"],
        ["$xorkey", "xordData"],
        ["powershell_payloads"],
        ["attackcode"],
        ["namespace PingCastle"],
        ["br.bat", "Breach.exe", "syspull.ps1"],
        #["Bruteforce", "password"],
        #["Brute-force", "password"],
        ["exploit", "vulnerbility", "cve-"],
        ["Privilege Escalation"],
        # Names of researchers / script authors for common offensive scripts that frequently show up in copied code.
        # Low hanging fruit - not necessarily always bad but increase risk.
        ["khr0x40sh"],
        ["harmj0y"],
        ["mattifestation"],
        ["FuzzySec"],
    ]

    #####################
    # Neutral Behaviors #
    #####################

    behaviorCol["Downloader"] = [
        ["DownloadFile"],
        ["DownloadString"],
        ["DownloadData"],
        ["WebProxy", "Net.CredentialCache"],
        ["Start-BitsTransfer"],
        ["bitsadmin"],
        ["Sockets.TCPClient", "GetStream"],
        ["$env:LocalAppData"],
        ["Invoke-WebRequest"],
        ["Net.WebRequest"],
        ["wget"],
        #["Get-Content"],
        ["send", "open", "responseBody"],
        ["HttpWebRequest", "GetResponse"],
        ["InternetExplorer.Application", "Navigate"],
        ["Excel.Workbooks.Open('http"],
        ["Notepad", "SendKeys", "ForEach-Object", "Clipboard", "http"],
        ["Excel.Workbooks.Open", "http", "ReleaseComObject", "Sheets", "Item", "Range", "Row"],
    ]

    behaviorCol["Starts Process"] = [
        ["Start-Process"],
        ["New-Object", "IO.MemoryStream", "IO.StreamReader"],
        ["Diagnostics.Process]::Start"],
        ["RedirectStandardInput", "UseShellExecute"],
        ["Invoke-Item"],
        ["WScript.Shell", "ActiveXObject", "run"],
        ["START", "$ENV:APPDATA", "exe", "http"],
    ]

    behaviorCol["Script Execution"] = [
        ["Invoke-Expression"],
        ["Invoke-Command"],
        ["InvokeCommand"],
        ["Invoke-Script"],
        ["InvokeScript"],
        [".Invoke("],
        ["IEX("],
        ["wScript.Run"],
        ["wscript.shell"],
        ["ActiveXObject", "ShellExecute"],
        ["$ExecutionContext|Get-Member)[6].Name"],  # Invoke-Command
        ["shellexecute"],
    ]

    behaviorCol["Compression"] = [
        ["Convert", "FromBase64String", "Text.Encoding"],
        ["IO.Compression.GzipStream"],
        ["Compression.CompressionMode]::Decompress"],
        ["IO.Compression.DeflateStream"],
        ["IO.MemoryStream"],
    ]

    behaviorCol["Hidden Window"] = [
        ["WindowStyle", "Hidden"],
        ["CreateNoWindow=$true"],
        ["Window.ReSizeTo 0, 0"],
    ]

    behaviorCol["Custom Web Fields"] = [
        ["Headers.Add"],
        ["SessionKey", "SessiodID"],
        ["Method", "ContentType", "UserAgent", "WebRequest]::create"],
    ]

    behaviorCol["Persistence"] = [
        ["New-Object", "-COMObject", "Schedule.Service"],
        ["SCHTASKS"],
    ]

    behaviorCol["Sleeps"] = [
        ["Start-Sleep"],
        ["sleep -s"],
    ]

    behaviorCol["Uninstalls Apps"] = [
        ["foreach", "UninstallString"],
    ]

    behaviorCol["Obfuscation"] = [
        ["-Join", "[int]", "-as", "[char]"],
        ["-bxor"],
        ["PtrToStringAnsi"],
    ]

    behaviorCol["Crypto"] = [
        ["Security.Cryptography.AESCryptoServiceProvider", "Mode", "Key", "IV"],
        ["CreateEncryptor().TransformFinalBlock"],
        ["CreateDecryptor().TransformFinalBlock"],
        ["Security.Cryptography.CryptoStream"],
        ["CreateAesManagedObject", "Mode", "Padding"],
        ["ConvertTo-SecureString", "-Key"],
    ]

    behaviorCol["Enumeration"] = [
        ["Environment]::UserDomainName"],
        ["Environment]::UserName"],
        ["$env:username"],
        ["Environment]::MachineName"],
        ["Environment]::GetFolderPath"],
        ["IO.Path]::GetTempPath"],
        ["$env:windir"],
        ["Win32_NetworkAdapterConfiguration"],
        ["Win32_OperatingSystem"],
        ["Win32_ComputerSystem"],
        ["Principal.WindowsIdentity]::GetCurrent"],
        ["Principal.WindowsBuiltInRole]", "Administrator"],
        ["Diagnostics.Process]::GetCurrentProcess"],
        ["PSVersionTable.PSVersion"],
        ["Diagnostics.ProcessStartInfo"],
        ["Win32_ComputerSystemProduct"],
        ["Get-Process -id"],
        ["$env:userprofile"],
        ["Forms.SystemInformation]::VirtualScreen"],
        ["ipconfig"],
        ["Win32_Processor", "AddressWidth"],
        ["GetHostAddresses"],
        ["IPAddressToString"],
        ["Get-Date"],
        ["HNetCfg.FwPolicy"],
        ["GetTokenInformation"],
    ]

    behaviorCol["Registry"] = [
        ["HKCU:\\"],
        ["HKLM:\\"],
        ["New-ItemProperty", "-Path", "-Name", "-PropertyType", "-Value"],
        ["reg add", "reg delete"],
    ]

    behaviorCol["Sends Data"] = [
        ["UploadData", "POST"],
    ]

    behaviorCol["Byte Usage"] = [  # Additional checks done in processing.
        ["AppDomain]::CurrentDomain.GetAssemblies()", "GlobalAssemblyCache"],
        ["[Byte[]] $buf"],
        ["IO.File", "WriteAllBytes"],
    ]

    behaviorCol["SysInternals"] = [
        ["procdump", "sysinternals"],
        ["psexec", "sysinternals"],
    ]

    behaviorCol["One Liner"] = [  # Work done in processing.
    ]

    behaviorCol["Variable Extension"] = [  # Work done in processing.
    ]

    ####################
    # Benign Behaviors #
    ####################

    behaviorCol["Script Logging"] = [
        ["LogMsg", "LogErr"],
        ["Write-Debug"],
        ["Write-Log"],
        ["Write-Host"],
        ["Exception.Message"],
        ["Write-Output"],
        ["Write-Warning"],
    ]

    behaviorCol["License"] = [
        ["# Copyright", "# Licensed under the"],
        ["Copyright (C)"],
        ["Permission is hereby granted"],
        ['THE SOFTWARE IS PROVIDED "AS IS"'],
        ["Begin signature block"]
    ]

    behaviorCol["Function Body"] = [
        [".SYNOPSIS", ".DESCRIPTION", ".EXAMPLE"],
        [".VERSION", ".AUTHOR", ".CREDITS"],
    ]

    behaviorCol["Positive Context"] = [
        ["createButton"],
        ["toolTip"],
        ["deferral"],
        ["Start-AutoLab"],
        ["Failed to download"],
        ["FORENSICS SNAPSHOT"],
        ["choclatey"],
        ["Chocolatey"],
        ["chef-client", "chef.msi"],
        ["Node.js", "nodejs.org"],
        ["sqlavengers"],
        ["SpyAdBlocker.lnk"],
        ["ReadMe.md"],
        ["Remote Forensic Snapshot"],
        ["Function Write-Log"],
        ["Remote Forensic Snapshot"],
    ]

    # Behavioral Combos combine a base grouping of behaviors to help raise the score of files without a lot of complexity.
    # Take care in adding to this list and use a minimum length of 3 behaviors.
    # Instances where FP hits occur have been commented out

    behaviorCombos = [
        ["Downloader", "One Liner", "Variable Extension"],
        ["Downloader", "Script Execution", "Crypto", "Enumeration"],
        ["Downloader", "Script Execution", "Persistence", "Enumeration"],
        ["Downloader", "Script Execution", "Starts Process", "Enumeration"],
        ["Script Execution", "One Liner", "Variable Extension"],
        #["Script Execution", "Starts Process", "Downloader"],
        ['Script Execution', 'Starts Process', 'Downloader', 'One Liner'],
        ['Script Execution', 'Downloader', 'Custom Web Fields'],
        #['Script Execution', 'Downloader', 'One Liner'],
        ["Script Execution", "Hidden Window", "Downloader"],
        ['Script Execution', 'Crypto', 'Obfuscation'],
        #['Starts Process', 'Downloader', 'Custom Web Fields'],
        #['Starts Process', 'Downloader', 'One Liner'],
        #["Starts Process", "Downloader", "Enumeration", "One Liner"],
        ["Hidden Window", "Persistence", "Downloader"],
    ]

    for behavior in behaviorCol:

        startTime = datetime.now()

        # Check Behavior Keyword/Combinations.
        for check in behaviorCol[behavior]:

            bhFlag = True

            for value in check:
                if value.lower() not in alternativeData.lower() and bhFlag:
                    bhFlag = None

            if bhFlag:

                if behavior not in behaviorTags:
                    behaviorTags.append(behavior)

                    if debugFlag:
                        print(check)

        # Separate Meta-Behavioral Checks.
        if behavior == "Obfuscation":

            obfType = None

            # Character Frequency Analysis (Original Script only).
            if (originalData.count("w") >= 500 or \
                originalData.count("4") >= 250 or \
                originalData.count("_") >= 250 or \
                originalData.count("D") >= 250 or \
                originalData.count("C") >= 200 or \
                originalData.count("K") >= 200 or \
                originalData.count("O") >= 200 or \
                originalData.count(":") >= 100 or \
                originalData.count(";") >= 100 or \
                originalData.count(",") >= 100 or \
                (originalData.count("(") >= 50 and originalData.count(")") >= 50) or \
                (originalData.count("[") >= 50 and originalData.count("]") >= 50) or \
                (originalData.count("{") >= 50 and originalData.count("}") >= 50)
            # Added a line count length to try and stop this triggering on long benigns.
            ) and len(re.findall("(\n|\r\n)", originalData.strip())) <= 50:

                if behavior not in behaviorTags:
                    behaviorTags.append(behavior)
                    obfType = "Char Frequency"

            # Check Symbol Usage.
            if len(re.findall("\\\_+/", alternativeData)) >= 50:

                if behavior not in behaviorTags:
                    behaviorTags.append(behavior)
                    obfType = "High Symbol"

            # Check unique high variable declaration (includes JavaScript).
            if len(list(set(re.findall("var [^ ]+ ?=", alternativeData)))) >= 40 or \
                len(list(set(re.findall("\\$\w+?(?:\s*)=", alternativeData)))) >= 40:

                if behavior not in behaviorTags:
                    behaviorTags.append(behavior)
                    obfType = "High Variable"

        if behavior == "Byte Usage":

            if len(re.findall("0x[A-F0-9a-f][A-F0-9a-f],", alternativeData)) >= 100:
                if behavior not in behaviorTags:
                    behaviorTags.append(behavior)

        if behavior == "One Liner":

            if len(re.findall("(\n|\r\n)", originalData.strip())) == 0:
                if behavior not in behaviorTags:
                    behaviorTags.append(behavior)

        if behavior == "Abnormal Size":

            if len(originalData) >= 1000000 or len(re.findall("(\n|\r\n)", originalData)) >= 5000:
                if behavior not in behaviorTags:
                    behaviorTags.append(behavior)

        if behavior == "Variable Extension":

            shortVars = len(re.findall(
                "(Set-Item Variable|SI Variable|Get-ChildItem Variable|LS Variable|Get-Item Variable|ChildItem Variable|Set-Variable|Get-Variable|DIR Variable|GetCommandName|(\.Value\|Member|\.Value\.Name))",
                originalData, re.IGNORECASE))
            asterikVars = len(re.findall("[A-Za-z0-9]\*[A-Za-z0-9]", originalData))

            if shortVars + asterikVars >= 10:
                if behavior not in behaviorTags:
                    behaviorTags.append(behavior)

        if behavior == "Code Injection":
            cf1, cf2, cf3 = None, None, None
            for entry in c1:
                if entry.lower() in alternativeData.lower() and not cf1:
                    cf1 = True
            for entry in c2:
                if entry.lower() in alternativeData.lower() and not cf2 and cf1:
                    cf2 = True
            for entry in c3:
                if entry.lower() in alternativeData.lower() and not cf3 and cf1 and cf2:
                    cf3 = True
            if cf1 and cf2 and cf3:
                if behavior not in behaviorTags:
                    behaviorTags.append(behavior)

        stopTime = datetime.now() - startTime
        if debugFlag:
            print("Behavior Check - %s: %s" % (behavior, stopTime))

    # Tries to catch download cradle PowerShell scripts where the obfuscation isn't identified.
    # Examples are heavy variable command usage for chaining/parsing.
    if len(behaviorTags) == 2 and "One Liner" in behaviorTags and (
            "http://" in alternativeData.lower() or \
            "https://" in alternativeData.lower()) and \
            ("Script Execution" in behaviorTags or \
             "Starts Process" in behaviorTags
            ):
        behaviorTags.append("Downloader")
        behaviorTags.append("Obfuscation")
        obfType = "Hidden Commands"

    # Applies identified Malware Family or Obfuscation Type to behavior.
    if family:
        behaviorTags.append("Known Malware:%s" % (family))

    if obfType:
        behaviorTags[behaviorTags.index("Obfuscation")] = ("Obfuscation:%s" % (obfType))

    # Tries to determine if any behavior combos exist - should always be last step.
    for comboRow in behaviorCombos:
        foundFlag = 1
        if len(comboRow) != len(behaviorTags):
            foundFlag = 0
        else:
            for behavior in comboRow:
                if behavior not in behaviorTags:
                    foundFlag = 0
        if foundFlag == 1:
            if "Malicious Behavior Combo" not in behaviorTags:
                behaviorTags.append("Malicious Behavior Combo")

    return behaviorTags


def family_finder(contentData):
    """
    Attempts to profile a Malware Family (typically PowerShell Attack Frameworks) via keywords or REGEX.
    In general, preference is to match against all lowercase strings, this way CaMeL CaSe is ignored.

    Args:
        contentData: Normalize/Unraveled PowerShell Script

    Returns:
        family: "PowerSploit"
    """
    family = None

    # Family: Magic Unicorn
    # Reference: https://github.com/trustedsec/unicorn
    if re.search("\$w \= Add\-Type \-memberDefinition \$[a-zA-Z0-9]{3,4} \-Name", contentData) or \
        (all(entry in contentData.lower() for entry in ["sv", "gv", "value.tostring"]) and \
         re.search("[a-zA-Z0-9+/=]{250,}", contentData)):

        if not family:
            family = "Magic Unicorn"

    if re.search("\$[a-zA-Z0-9]{5,7} \= \'\[DllImport.+Start\-sleep 60\}\;", contentData):

        if not family:
            family = "Magic Unicorn Modified"

    # Family: Shellcode Injector (variant of Unicorn prior to randomization)
    # Reference: N/A
    if re.search("(\$c = |\$1 = [\"\']\$c = )", contentData) and \
        all(entry in contentData.lower() for entry in ["$g = 0x1000", "$z.length -gt 0x1000", "$z[$i]"]):

        if not family:
            family = "Shellcode Injector"

    # Family: ICMP Shell
    # Reference: https://github.com/inquisb/icmpsh
    if all(entry in contentData.lower() for entry in ["buffer", "getstring", "getbytes", "networkinformation.ping", "dontfragment"]) or \
        all(entry in contentData.lower() for entry in ["icmpsh", "nishang"]) or \
        "invoke-powershellicmp" in contentData.lower():

        if not family:
            family = "ICMP Shell"

    # Family: Social Engineering Toolkit (SET)
    # Reference: https://github.com/trustedsec/social-engineer-toolkit
    if re.search("\$code \= [\']{1,2}\[DllImport", contentData) or \
        any(entry in contentData.lower() for entry in ["$sc.length -gt 0x1000)", "$winfunc::memset"]):

        if not family:
            family = "SET"

    # Family: PowerDump
    # Reference: https://github.com/trustedsec/social-engineer-toolkit/blob/master/src/powershell/powerdump.powershell
    if all(entry in contentData.lower() for entry in ["function loadapi", "$code = @"]) or \
        "invoke-powerdump" in contentData.lower():

        if not family:
            family = "PowerDump"

    # Family: BashBunny
    # Reference: https://github.com/hak5/bashbunny-payloads/blob/master/payloads/library/Incident_Response/Hidden_Images/run.ps1
    if any(entry in contentData.lower() for entry in ["bashbunny", "loot\hidden-image-files"]):

        if not family:
            family = "BashBunny"

    # Family: Veil
    # Reference: https://github.com/yanser237/https-github.com-Veil-Framework-Veil-Evasion/blob/master/modules/payloads/powershell/shellcode_inject/virtual.py
    if any(entry in contentData.lower() for entry in ["0x1000,0x3000,0x40", "start-sleep -second 100000"]):

        if not family:
            family = "Veil Embed"

    if all(entry in contentData.lower() for entry in [
        "invoke-expression $(new-object io.streamreader ($(new-object io.compression.deflatestream",
        ")))), [io.compression.compressionmode]::decompress)), [text.encoding]::ascii)).readtoend();"]):

        if not family:
            family = "Veil Stream"

    # Family: PowerWorm
    # Reference: https://github.com/mattifestation/PowerWorm/blob/master/PowerWorm_Part_5.ps1
    if all(entry in contentData.lower() for entry in ["bootstrapped 100%", ".onion/get.php?s=setup"]):

        if not family:
            family = "PowerWorm"

    # Family: PowerShell Empire
    # Reference: https://github.com/EmpireProject/Empire/blob/293f06437520f4747e82e4486938b1a9074d3d51/lib/common/stagers.py#L344
    # Reference: https://github.com/EmpireProject/Empire/blob/master/lib/listeners/http_com.py
    # Reference: https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/userland/registry.py
    # Reference: https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/userland/schtasks.py
    # Reference: https://github.com/EmpireProject/Empire/blob/master/lib/listeners/http_hop.py

    if any(entry in contentData.lower() for entry in [
        "|%{$_-bxor$k[$i++%$k.length]};iex",
        "$wc=new-object system.net.webclient;$u='mozilla/5.0 (windows nt 6.1; wow64; trident/7.0; rv:11.0) like gecko';$wc.headers.add('user-agent',$u);$wc.proxy = [system.net.webrequest]::defaultwebproxy;$wc.proxy.credentials = [system.net.credentialcache]::defaultnetworkcredentials;",
        "{$gps['scriptblockLogging']['enablescriptblocklogging']=0;$gps['scriptblockLogging']['enablescriptblockinvocationlogging']=0}else{[scriptblock]",
        "$r={$d,$k=$args;$S=0..255;0..255|%{$J=($j+$s[$_]",
        "$iv=$data[0..3];$data=$data[4..$data.length];-join[char[]](& $r $data ($iv+$k)",
        "invoke-winenum",
        "invoke-postexfil",
        "invoke-empire",
        "get-posthashdumpscript",]) or \
        all(entry in contentData.lower() for entry in [
            "schtasks.exe",
            'powershell.exe -noni -w hidden -c "iex ([text.encoding]::unicode.getstring([convert]::frombase64string']) or \
        re.search("\$RegPath = .+\$parts = \$RegPath\.split.+\$path = \$RegPath\.split", contentData, re.IGNORECASE) or \
        all(entry in contentData.lower() for entry in ["shellcode1", "shellcode2", "getcommandlineaaddr"]) or \
        all(entry in contentData.lower() for entry in ["empireip", "empireport", "empirekey"]):

        if not family:
            family = "PowerShell Empire"

    # Family: Powerfun
    # Reference: https://github.com/rapid7/metasploit-framework/blob/cac890a797d0d770260074dfe703eb5cfb63bd46/data/exploits/powershell/powerfun.ps1
    # Reference: https://github.com/rapid7/metasploit-framework/pull/5194
    if all(entry in contentData.lower() for entry in ["new-object system.net.sockets.tcpclient", "$sendback2 = $sendback"]):

        if not family:
            family = "Powerfun Bind"

    if re.search("\$s\=New\-Object IO\.MemoryStream\(,\[Convert\]::FromBase64String\([\'\"]{1,2}H4sIA[a-zA-Z0-9+/=]+[\'\"]{1,2}\)\)\;IEX \(New\-Object IO\.StreamReader\(New\-Object IO\.Compression\.GzipStream\(\$s,\[IO\.Compression\.CompressionMode\]::Decompress\)\)\)\.ReadToEnd\(\)", contentData, re.IGNORECASE):

        if not family:
            family = "Powerfun Reverse"

    # Family: Mimikatz
    # Reference: https://github.com/gentilkiwi/mimikatz
    if all(entry in contentData.lower() for entry in ["dumpcred", "dumpcert", "customcommand"]) or \
        all(entry in contentData.lower() for entry in ["virtualprotect.invoke", "memcpy.invoke", "getcommandlineaaddr"]) or \
        all(entry in contentData.lower() for entry in ["[parameter(parametersetname = ", ", position = 1)]", "[switch]", "autolayout", "ansiclass"]) or \
        any(entry in contentData.lower() for entry in ["invoke-mimikatz", "$thisisnotthestringyouarelookingfor"]):

        if not family:
            family = "Mimikatz"

    # Family: Mimikittenz
    # Reference: https://github.com/putterpanda/mimikittenz/
    if any(entry in contentData.lower() for entry in ["inspectproc", "readprocessmemory", "mimikittenz"]):

        if not family:
            family = "Mimikittenz"

    # Family: PowerSploit
    # Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-TimedScreenshot.ps1
    # Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1
    if all(entry in contentData.lower() for entry in ["function get-timedscreenshot", "#load required assembly"]) or \
        any(entry in contentData.lower() for entry in ["invoke-reflectivepeinjection", "powersploit", "invoke-privesc", "invoke-dllinjection"]):

        if not family:
            family = "PowerSploit"

    if any(entry in contentData.lower() for entry in ["powerview", "invoke-userhunter", "invoke-stealthuserhunter", "invoke-processhunter", "invoke-usereventhunter"]):

        if not family:
            family = "PowerSploit PowerView"

    # Family: DynAmite Launcher (DynAmite Keylogger function is an old version of PowerSploit Get-Keystrokes)
    # Reference: https://webcache.googleusercontent.com/search?q=cache:yKX6QDiuHHMJ:https://leakforums.net/thread-712268+&cd=3&hl=en&ct=clnk&gl=us
    # Reference: https://github.com/PowerShellMafia/PowerSploit/commit/717950d00c7cc352efe8b05c3db84d0e6250474c#diff-8a834e13c96d5508df5ee11bc92c82dd
    if any(entry in contentData.lower() for entry in ['schtasks.exe /create /tn "microsoft\\windows\\dynamite']):

        if not family:
            family = "DynAmite Launcher"

    if any(entry in contentData.lower() for entry in ["function dynakey"]):

        if not family:
            family = "DynAmite KeyLogger"

    # Family: Invoke-Obfuscation
    # Reference: https://github.com/danielbohannon/Invoke-Obfuscation/blob/master/Out-ObfuscatedStringCommand.ps1
    if all(entry in contentData.lower() for entry in ["shellid[1]", "shellid[13]"]):

        if not family:
            family = "Invoke-Obfuscation"

    # Family: TXT C2
    # Reference: N/A
    if re.search("if\([\"\']{2}\+\(nslookup \-q=txt", contentData) and re.search(
        "\) \-match [\"\']{1}@\(\.\*\)@[\"\']{1}\)\{iex \$matches\[1\]\}", contentData):

        if not family:
            family = "TXT C2"

    # Family: Remote DLL
    # Reference: N/A
    if any(entry in contentData.lower() for entry in ["regsvr32 /u /s /i:http"]):

        if not family:
            family = "Remote DLL"

    # Family: Cobalt Strike
    # Reference: https://www.cobaltstrike.com/
    if any(entry in contentData.lower() for entry in ["$doit = @"]) or \
        all(entry in contentData.lower() for entry in ["func_get_proc_address", "func_get_delegate_type", "getdelegateforfunctionpointer", "start-job"]):

        if not family:
            family = "Cobalt Strike"

    # Family: vdw0rm
    # Reference: N/A
    if any(entry in contentData.lower() for entry in ["vdw0rm", "*-]nk[-*"]):

        if not family:
            family = "vdw0rm"

    # Family: Emotet
    # Reference: N/A
    if all(entry in contentData.lower() for entry in ["invoke-item", "get-item", "length -ge 40000", "break"]):

        if not family:
            family = "Emotet"

    # Family: mateMiner 2.0
    # Reference: http://wolvez.club/2018/11/10/mateMinerKiller/
    if all(entry in contentData.lower() for entry in ["killbot", "mimi", "sc"]):

        if not family:
            family = "mateMiner"

    # Family: DownAndExec
    # Reference: https://www.welivesecurity.com/2017/09/13/downandexec-banking-malware-cdns-brazil/
    if all(entry in contentData.lower() for entry in ["downandexec", "cdn", "set cms="]):

        if not family:
            family = "DownAndExec"

    # Family: Buckeye / Filensfer
    # Reference: https://www.kernelmode.info/forum/viewtopic.php?t=5533
    if all(entry in contentData.lower() for entry in ["error, byebye!", "string re_info", "sockargs"]):

        if not family:
            family = "Buckeye"

    # Family: APT34
    # Reference: https://www.jishuwen.com/d/2K6t
    if any(entry in contentData.lower() for entry in ["global:$cca", "$ffa = $eea", "$ssa = $qqa"]):

        if not family:
            family = "APT34"

    # Family: MuddyWater
    # Reference: https://blog.talosintelligence.com/2019/05/recent-muddywater-associated-blackwater.html
    if all(entry in contentData.lower() for entry in ["clientfrontLine", "helloserver", "getcommand"]) or \
        all(entry in contentData.lower() for entry in ["projectcode", "projectfirsthit", "getcmdresult"]) or \
        all(entry in contentData.lower() for entry in ["basicinfocollector", "getclientidentity", "executecommandandsetcommandresultrequest"]):

        if not family:
            family = "MuddyWater"

    # Family: Tennc Webshell
    # Reference: https://github.com/tennc/webshell
    if all(entry in contentData.lower() for entry in ['getparameter("z0")', 'import="java.io.*']):

        if not family:
            family = "Tennc Webshell"

    # Family: PoshC2
    # Reference: https://github.com/nettitude/PoshC2
    if all(entry in contentData.lower() for entry in ["function get-key", "importdll", "check for keys not mapped by virtual keyboard"]) or \
        any(entry in contentData.lower() for entry in ["poshc2", "powershellc2"]):

        if not family:
            family = "PoshC2"

    # Family: Posh-SecMod
    # Reference: https://github.com/darkoperator/Posh-SecMod
    if any(entry in contentData.lower() for entry in ["posh-secmod", ]):

        if not family:
            family = "Posh-SecMod"

    # Family: Invoke-TheHash
    # Reference: https://github.com/Kevin-Robertson/Invoke-TheHash
    if any(entry in contentData.lower() for entry in ["new-packetsmb2findrequestfile", "packet_smb2b_header", "new-packetntlmssp"]):

        if not family:
            family = "Invoke-TheHash"

    # Family: Nishang
    # Reference: https://github.com/samratashok/nishang
    if any(entry in contentData.lower() for entry in ["nishang"]):

        if not family:
            family = "Nishang"

    # Family: Invoke-CradleCrafter
    # Reference:
    if any(entry in contentData.lower() for entry in ["invoke-cradlecrafter", "postcradlecommand"]):

        if not family:
            family = "Invoke-CradleCrafter"

    return family


###########################################
# De-obfuscation / Normalization Functions #
###########################################


def removeNull(contentData, modificationFlag):
    """
    Windows/Unicode introduces NULL bytes will interfere with string and REGEX pattern matching.

    Args:
        contentData: "\x00H\x00e\x00l\x00l\x00o"
        modificationFlag: Boolean

    Returns:
        contentData: "Hello"
        modificationFlag: Boolean
    """
    startTime = datetime.now()

    modificationFlag = True

    if debugFlag:
        print("\t[!] Removed NULLs - %s: %s" % (modificationFlag, datetime.now() - startTime))

    return contentData.replace("\x00", "").replace("\\x00", ""), modificationFlag


def formatReplace(contentData, modificationFlag):
    """
    Attempts to parse PowerShell Format Operator by re-ordering substrings into the main string.
    Due to flexibility of language, it tries to identify nested versions first and unwrap it inside-out.

    Args:
        contentData: 'This is an ("{1}{0}{2}" -F"AMP","EX", "LE")'
        modificationFlag: Boolean

    Returns:
        contentData: 'This is an "EXAMPLE"'
        modificationFlag: Boolean
    """
    startTime = datetime.now()
    obfGroup = None

    try:
        # Inner most operators, may not contain strings potentially with nested format operator layers ("{").
        obfGroup = re.search(
            r"\((?:\s*)(\"|\')((?:\s*)\{[0-9]{1,3}\}(?:\s*))+\1(?:\s*)-[fF](?:\s*)(\"|\')[^{]+?(\"|\')(?:\s*)\)",
            contentData).group()
    except:

        try:
            # General capture of format operators without nested values.
            # Replaced LF with 0x01 simply to have a place holder to return the string back to later.
            obfGroup = re.search(
                r"\((?:\s*)(\"|\')((?:\s*)\{[0-9]{1,3}\}(?:\s*))+\1(?:\s*)-[fF](?:\s*)(\"|\').+?(\"|\')(?:\s*)\)(?![^)])",
                contentData.replace("\n", "\x01")).group()

        except:
            # Final attempt by removing all LF - will potentially modify input string greatly
            obfGroup = re.search(
                r"\((?:\s*)(\"|\')((?:\s*)\{[0-9]{1,3}\}(?:\s*))+\1(?:\s*)-[fF](?:\s*)(\"|\').+?(\"|\')(?:\s*)\)(?![^)])",
                contentData.replace("\n", "")).group()

            if obfGroup:
                contentData = contentData.replace("\n", "")

    builtString = formatBuidler(obfGroup)

    contentData = contentData.replace(obfGroup.replace("\x01", "\n"), '"' + builtString + '"').replace("\x01", "\n")

    modificationFlag = True

    if debugFlag:
        print("\t[!] Format Replaced - %s: %s" % (modificationFlag, datetime.now() - startTime))

    return contentData, modificationFlag


def formatBuidler(obfGroup):
    """
    Supporting function for formatReplace() that will try to build format operator indexes and rebuild strings.

    Args:
        obfGroup: '("{1}{0}{2}" -F"AMP",'EX', "LE")'

    Returns:
        contentData: 'EXAMPLE'
    """
    # Builds an index list from the placeholder digits.
    indexList = [int(x) for x in re.findall("\d+", obfGroup.split("-")[0])]

    stringList = "-".join(obfGroup.split("-")[1:])[1:-1]
    stringList = [x[0][1:-1] for x in re.findall(r"((\"|\').+?(?<!`)(\2))", stringList)]

    contentData = list()

    for entry in indexList:
        if entry < len(stringList):
            contentData.append(stringList[entry])

    contentData = "".join(contentData)

    return contentData


def removeEscapeQuote(contentData, modificationFlag):
    """
    Removes escaped quotes. These will freqently get in the way for string matching over longer structures.

    Args:
        contentData: b"This is an \\"EXAMPLE\\""
        modificationFlag: Boolean

    Returns:
        contentData: b'This is an "EXAMPLE"'
        modificationFlag: Boolean
    """
    startTime = datetime.now()

    counter = 0

    # Replace blank quotes first so as to not cause issues with following replacements
    contentData = contentData.replace("\\'\\'", "").replace('\\"\\"', "")

    for entry in re.findall(r"([^'])(\\\')", contentData):
        contentData = contentData.replace("".join(entry), entry[0] + "'")
        modificationFlag = True
        counter +=1

    for entry in re.findall(r'([^"])(\\\")', contentData):
        contentData = contentData.replace("".join(entry), entry[0] + '"')
        modificationFlag = True
        counter += 1

    if debugFlag:
        print("\t[!] Removed Escaped Quotes - %s: %s _ %s" % (modificationFlag, datetime.now() - startTime, counter))

    return contentData, modificationFlag


def removeEmptyQuote(contentData, modificationFlag):
    """
    Removes Empty Quotes which can be used as obfuscation to break strings apart.

    Args:
        contentData: "EXA''MPLE"
        modificationFlag: Boolean

    Returns:
        contentData: "EXAMPLE"
        modificationFlag: Boolean
    """
    startTime = datetime.now()

    modificationFlag = True

    if debugFlag:
        print("\t[!] Removed Empty Quotes - %s: %s" % (modificationFlag, datetime.now() - startTime))

    return contentData.replace("''", "").replace('""', ''), modificationFlag


def removeTick(contentData, modificationFlag):
    """
    Removes Back Ticks which can be used as obfuscation to break strings apart.

    Args:
        contentData: "$v`a`r=`'EXAMPLE'`"
        modificationFlag: Boolean

    Returns:
        contentData: "$var='EXAMPLE'"
        modificationFlag: Boolean
    """
    startTime = datetime.now()

    modificationFlag = True

    if debugFlag:
        print("\t[!] Removed Back Ticks - %s: %s" % (modificationFlag, datetime.now() - startTime))

    return contentData.replace("`", ""), modificationFlag


def removeCaret(contentData, modificationFlag):
    """
    Removes Caret which can be used as obfuscation to break strings apart.

    Args:
        contentData: "$v^a^r=^'EXAMPLE'^"
        modificationFlag: Boolean

    Returns:
        contentData: "$var='EXAMPLE'"
        modificationFlag: Boolean
    """
    startTime = datetime.now()

    modificationFlag = True

    if debugFlag:
        print("\t[!] Removed Carets - %s: %s" % (modificationFlag, datetime.now() - startTime))

    return contentData.replace("^", ""), modificationFlag


def spaceReplace(contentData, modificationFlag):
    """
    Converts two spaces to one.

    Args:
        contentData: "$var=    'EXAMPLE'"
        modificationFlag:

    Returns:
        contentData: "$var= 'EXAMPLE'"
        modificationFlag: Boolean
    """

    return contentData.replace("  ", " "), modificationFlag


def charReplace(contentData, modificationFlag):
    """
    Attempts to convert PowerShell char data types using Hex and Int values into ASCII.

    Args:
        contentData: [char]101
        modificationFlag: Boolean

    Returns:
        contentData: "e"
        modificationFlag: Boolean
    """
    startTime = datetime.now()

    #  Hex needs to go first otherwise the 0x gets gobbled by second Int loop/PCRE (0x41 -> 65 -> "A")
    for value in re.findall("\[char\]0x[0-9a-z]{1,2}", contentData):
        charConvert = int(value.split("]")[1], 0)
        if 10 <= charConvert <= 127:
            contentData = contentData.replace(value, '"%s"' % chr(charConvert))
            modificationFlag = True

    # Int values
    for value in re.findall("\[char\][0-9]{1,3}", contentData, re.IGNORECASE):
        charConvert = int(value.split("]")[1])
        if 10 <= charConvert <= 127:
            contentData = contentData.replace(value, '"%s"' % chr(charConvert))
            modificationFlag = True

    if debugFlag:
        print("\t[!] Char Replace - %s: %s" % (modificationFlag, datetime.now() - startTime))

    return contentData, modificationFlag


def typeConversion(contentData, modificationFlag):
    """
    Attempts to identify Int (various bases), 0xHex, and \\xHex formats in comma-delimited lists for conversion to ASCII.

    Args:
        contentData: "69,88,65,77,80,76,69"
        modificationFlag: Boolean

    Returns:
        contentData: "EXAMPLE"
        modificationFlag: Boolean
    """
    startTime = datetime.now()
    counter = 0

    for baseValue in [0, 8, 16, 32]:

        baseString = str()

        for entry in re.findall(r"([1-2]?[0-9][0-9](?:\s*),|0x[0-9a-fA-F]{1,2}(?:\s*),|\\x[0-9a-fA-F]{1,2}(?:\s*),)", contentData.replace(" ", "")):
            entry = re.search("[A-Fa-f0-9]+", entry.replace("0x", "")).group()
            if entry != "0":
                try:
                    counter += 1
                    charConvert = int(entry, baseValue)
                    if 10 <= charConvert <= 127:
                        baseString += chr(charConvert)
                except:
                    pass

        baseString = stripASCII(baseString)

        # Additional checks to make sure we're not in a loop
        if baseString not in garbageList and not any(x in baseString for x in garbageList) and len(baseString) > 50:
            contentData += "\n\n##### TYPE CONVERSION #####\n\n%s\n\n" % (baseString)
            garbageList.append(baseString)
            modificationFlag = True

    if debugFlag:
        print("\t[!] Type Conversion - %s: %s _ %s" % (modificationFlag, datetime.now() - startTime, counter))

    return contentData, modificationFlag


def stringSplit(contentData, modificationFlag):
    """
    Attempts to split strings and combine them back with a comma.
    Primarily targeting lists of bytes for type conversion.

    Args:
        contentData: "HAeBlBlCo".split("ABC")
        modificationFlag: Boolean

    Returns:
        contentData: "H,e,l,l,o"
        modificationFlag: Boolean
    """
    startTime = datetime.now()

    splitString = re.search(r"\.split\((\'|\")[^\'\"]+?\1\)", contentData, re.IGNORECASE).group()
    delimSplit = [x for x in splitString[8:-2]]
    checkStrings = re.findall(r"((\'|\")[^\2]+?\2)", contentData)

    if delimSplit != [] and delimSplit != [" "] and len(delimSplit) < 10:
        contentData = contentData.replace(splitString, "")

        for entry in checkStrings:
            strippedString = entry[0][1:-1]
            for x in delimSplit:
                if x in entry[0]:
                    # Sets to "comma" as a separator so typeConversion can pick it up on next run
                    strippedString = strippedString.replace(x, ",")

                    if strippedString not in garbageList:
                        garbageList.append(entry[0])
                        contentData += "\n\n##### SPLIT STRINGS #####\n\n%s\n\n" % (strippedString)
                        modificationFlag = True

    if debugFlag:
        print("\t[!] Split Strings - %s: %s" % (modificationFlag, datetime.now() - startTime))

    return contentData, modificationFlag


def joinStrings(contentData, modificationFlag):
    """
    Joins strings together where a quote is followed by a concatenation and another quote.

    Args:
        contentData: "$var=('EX'+'AMP'+'LE')"
        modificationFlag: Boolean

    Returns:
        contentData: "$var=('EXAMPLE')"
        modificationFlag: Boolean
    """
    startTime = datetime.now()

    for entry in re.findall("(?:\"|\')(?:\s*)\+(?:\s*)(?:\"|\')", contentData):
        contentData = contentData.replace(entry, "")
        modificationFlag = True

    if debugFlag:
        print("\t[!] Joined Strings - %s: %s" % (modificationFlag, datetime.now() - startTime))

    return contentData, modificationFlag


def replaceDecoder(contentData, modificationFlag):
    """
    Attempts to replace strings across the content that use the Replace function.

    Args:
        contentData: "(set GmBtestGmb).replace('GmB',[Char]39)"
        modificationFlag: Boolean

    Returns:
        contentData: "set 'test'"
        modificationFlag: Boolean
    """
    startTime = datetime.now()

    # Clean up any chars or byte values before replacing
    contentData, modificationFlag = charReplace(contentData, None)

    # Group 0 = Full Line, Group 3 = First, Group 6 = Second.
    # Second replace can be empty so * instead of +, first may never be empty.
    replaceStrings = re.findall(r"((?:replace)(?:\s*)\(?(?:\s*)\(?(?:([^(\'|\")])*)(\'|\")([^\3]*?)\3(?:[^,]*?),(?:\s*)\(?(?:([^(\'|\")])*)(\'|\")([^\6]*?)\6(?:\s*)\)?(?:\s*)\)?)",
        contentData, re.IGNORECASE
    )

    for entry in replaceStrings:
        # Length check to compensate for replace statements without a defined replacement.
        # Without length check, when it defaults to nothing, it can cause REGEX pattern to over match.
        if entry[3] != "" and entry[0] not in garbageList and len(entry[0]) < 30:
            garbageList.append(entry[0])
            contentData = contentData.replace(entry[3], entry[6])
            modificationFlag = True

    if debugFlag:
        print("\t[!] Replaced Strings - %s: %s" % (modificationFlag, datetime.now() - startTime))

    return contentData, modificationFlag


########################
# Unraveling Functions #
########################


def reverseStrings(originalData, contentData, modificationFlag):
    """
    Reverses content and appends it to the modified data blob.

    Args:
        originalData: marap
        contentData: example
        modificationFlag: Boolean

    Returns:
        contentData: example param
        modificationFlag: Boolean

    """
    startTime = datetime.now()

    reverseMsg = originalData[::-1]

    if reverseMsg not in garbageList:
        contentData += "\n\n##### REVERSED CONTENT #####\n\n%s\n\n" % (reverseMsg)
        garbageList.append(reverseMsg)
        modificationFlag = True

    if debugFlag:
        print("\t[!] Reversed Strings - %s: %s" % (modificationFlag, datetime.now() - startTime))

    return contentData, modificationFlag


def decompressContent(contentData, modificationFlag):
    """
    Attempts to decompress content using various algorithms (zlib/gzip/etc).

    Args:
        contentData: String of Base64 content
        modificationFlag: Boolean

    Returns:
        contentData: Decompressed content of ASCII printable
    """
    startTime = datetime.now()

    for entry in re.findall("[A-Za-z0-9+/=]{40,}", contentData):
        try:  # Wrapped in try/except because both strings can appear but pipe through unrelated Base64.
            decompressMsg = decompressData(entry)
            if decompressMsg:
                if decompressMsg not in garbageList:
                    contentData += "\n\n##### DECOMPRESS CONTENT #####\n\n%s\n\n" % (decompressMsg)
                    garbageList.append(decompressMsg)
                    modificationFlag = True
        except:
            pass

    if debugFlag:
        print("\t[!] Decompressed Content - %s: %s" % (modificationFlag, datetime.now() - startTime))

    return contentData, modificationFlag


def decompressData(contentData):
    """
    Handles the actual decompression of Base64 data.

    Args:
        contentData: String of Base64 content

    Returns:
        contentData: Decompressed content of ASCII printable

    """
    decoded = base64.b64decode(contentData)
    # IO.Compression.DeflateStream
    try:
        # 15 is the default parameter
        contentData = zlib.decompress(decoded, 15)  # zlib
    except:
        pass
    try:
        # -15 makes it ignore the gzip header
        contentData = zlib.decompress(decoded, -15)  # zlib
    except:
        pass
    try:
        contentData = zlib.decompress(decoded, -zlib.MAX_WBITS)  # deflate
    except:
        pass
    try:
        contentData = zlib.decompress(decoded, 16 + zlib.MAX_WBITS)  # gzip
    except:
        pass

    contentData = stripASCII(contentData)

    return contentData


def decodeBase64(contentData, modificationFlag):
    """
    Attempts to decode Base64 content.

    Args:
        contentData: Encoded Base64 string
        modificationFlag: Boolean

    Returns:
        contentData: Decoded Base64 string
        modificationFlag: Boolean
    """
    startTime = datetime.now()

    for entry in re.findall("[A-Za-z0-9+/=]{30,}", contentData):
        try:
            # In instances where we have a broken/fragmented Base64 string.
            # Try to subtract to the lower boundary than attempting to add padding.
            while len(entry) % 4:
                entry = entry[:-1]

            b64data = base64.b64decode(entry)
            baseString = stripASCII(b64data)

            if baseString not in garbageList:
                contentData += "\n\n##### B64 CONTENT #####\n\n%s\n\n" % (baseString)
                garbageList.append(baseString)
                modificationFlag = True
        except:
            pass

    if debugFlag:
        print("\t[!] Decoded Base64 - %s: %s" % (modificationFlag, datetime.now() - startTime))

    return contentData, modificationFlag


def decryptStrings(contentData, modificationFlag):
    """
    Attempts to decrypt Microsoft SecureStrings using AES-CBC.

    Args:
        contentData: Content with key and encrypted SecureString
        modificationFlag: Boolean

    Returns:
        contentData: Decrypted content
        modificationFlag: Boolean
    """
    startTime = datetime.now()

    for entry in re.findall("[A-Za-z0-9+/=]{250,}", contentData):
        try:  # Wrapped in try/except since we're effectively brute forcing

            for key in re.findall("(?:[0-9]{1,3},){15,}[0-9]{1,3}", contentData.replace(" ", "")):

                decompressMsg = decryptData(entry, key)
                if decompressMsg:
                    if decompressMsg not in garbageList:
                        contentData += "\n\n##### DECRYPTED CONTENT #####\n\n%s\n\n" % (decompressMsg)
                        garbageList.append(decompressMsg)
                        modificationFlag = True
        except:
            pass

    if debugFlag:
        print("\t[!] Decrypted Content - %s: %s" % (modificationFlag, datetime.now() - startTime))

    return contentData, modificationFlag


def decryptData(contentData, key):
    """
    Handles the actual AES-CBC decryption.

    Args:
        contentData: SecureString Base64 Content (contains IV and encrypted data)
        key: AES CBC Key

    Returns:
        contentData: Decrypted content
    """
    # Possibly a better indicator "76492d1116743f0" for start header of Base64 content using this method.

    data = base64.b64decode(contentData)
    data = data.replace(b"\x00", b"")
    data = data.split(b"|")

    iv = base64.b64decode(data[1])
    data = binascii.unhexlify(data[2])
    key = "".join([chr(y) for y in [int(x) for x in key.split(",")]])
    key = key.encode("raw_unicode_escape")

    decrypt = AES.new(key, AES.MODE_CBC, iv)
    decrypt = decrypt.decrypt(data)

    contentData = decrypt.replace(b"\x00", b"").decode().strip()

    return contentData


########################
# Processing Functions #
########################


def normalize(contentData):
    """
    The primary normalization and de-obfuscation function. Runs various checks and changes as necessary.

    Args:
        contentData: Script content

    Returns:
        contentData: Normalized / De-Obfuscated content
    """

    # Passes modificationFlag to each function to determine whether or not it should try to normalize the new content.
    while True:

        modificationFlag = None
        if debugFlag:
            print("[+] Normalization Function")

        # Remove Null Bytes - Changes STATE
        # Keep this one first so that further PCRE work as expected.
        if re.search("(\x00|\\\\x00)", contentData):
            contentData, modificationFlag = removeNull(contentData, modificationFlag)

        # Rebuild format operator replacements - Changes STATE
        while re.search(
                r'\((?:\s*)(\"|\')((?:\s*)\{[0-9]{1,3}\}(?:\s*))+\1(?:\s*)-[fF](?:\s*)(?!.*\{\d\})(?:(\"|\').+?(\"|\'))(?:\s*)\)',
                contentData) or re.search(
            r'\((?:\s*)(\"|\')((?:\s*)\{[0-9]{1,3}\}(?:\s*))+\1(?:\s*)-[fF](?:\s*)(\"|\').+?(\"|\')(?:\s*)\)',
            contentData.replace("\n", "")):
            contentData, modificationFlag = formatReplace(contentData, modificationFlag)

        # Un-Escape Quotes - Changes STATE
        if re.search(r"([^'])(\\')", contentData) or re.search(r'([^"])(\\")', contentData):
            contentData, modificationFlag = removeEscapeQuote(contentData, modificationFlag)

        # Remove Empty Quotes - Changes STATE
        if "''" in contentData or '""' in contentData:
            contentData, modificationFlag = removeEmptyQuote(contentData, modificationFlag)

        # Remove Back Tick - Changes STATE
        if "`" in contentData:
            contentData, modificationFlag = removeTick(contentData, modificationFlag)

        # Remove Caret - Changes STATE
        if "^" in contentData:
            contentData, modificationFlag = removeCaret(contentData, modificationFlag)

        # Removes Space Padding - Does NOT change STATE
        while re.search("[\x20]{2,}", contentData):
            contentData, modificationFlag = spaceReplace(contentData, modificationFlag)

        # Converts Char bytes to ASCII - Changes STATE
        if re.search("\[char\](0x)?[0-9A-Fa-f]{1,3}", contentData, re.IGNORECASE):
            contentData, modificationFlag = charReplace(contentData, modificationFlag)

        # Type conversions - Changes STATE
        if re.search(r"([1-2]?[0-9]?[0-9](?:\s*),|0x[0-9a-fA-F]{1,2}(?:\s*),|\\x[0-9a-fA-F]{1,2}(?:\s*),)", contentData):
            contentData, modificationFlag = typeConversion(contentData, modificationFlag)

        # String Splits - Changes STATE
        if re.search(r"\.split\((\'|\")[^\'\"]+?\1\)", contentData, re.IGNORECASE):
            contentData, modificationFlag = stringSplit(contentData, modificationFlag)

        # Bridge strings together - Changes STATE
        if re.search("(\"|\')(?:\s*)\+(?:\s*)(\"|\')", contentData):
            contentData, modificationFlag = joinStrings(contentData, modificationFlag)

        # Replace strings - Changes STATE
        # Leave this one last after other formatting has completed
        if re.search(
                r'((?:replace)(?:\s*)\((?:\s*)\(?(?:([^(\'|\")])*)(\'|\")([^(\3)]+?)\3(?:[^,]*?),(?:\s*)\(?(?:([^(\'|\")])*)(\'|\")([^(\6)]*?)\6(?:\s*)\)?(?:\s*)\))',
                contentData, re.IGNORECASE):
            contentData, modificationFlag = replaceDecoder(contentData, modificationFlag)

        if modificationFlag == None:
            break

    return contentData


def unravelContent(originalData):
    """
    This is the primary function responsible for creating an alternate data stream of unraveled data.

    Args:
        contentData: Script content

    Returns:
        contentData: Unraveled additional content
    """
    contentData = normalize(originalData)
    loopCount = 0

    while True:

        modificationFlag = None

        # Reversed Strings - Changes STATE
        # Looks only in originalData, can be problematic flipping unraveled content back and forth.
        reverseString = ["noitcnuf", "marap", "nruter", "elbairav", "tcejbo-wen", "ecalper",]
        if any(entry in originalData.lower() for entry in reverseString):
            contentData, modificationFlag = reverseStrings(originalData, contentData, modificationFlag)

        # Decompress Streams - Changes STATE
        if all(entry in contentData.lower() for entry in ["streamreader", "frombase64string"]) or \
            all(entry in contentData.lower() for entry in ["deflatestream", "decompress"]) or \
            all(entry in contentData.lower() for entry in ["memorystream", "frombase64string"]):
            contentData, modificationFlag = decompressContent(contentData, modificationFlag)

        # Base64 Decodes - Changes STATE
        if re.search("[A-Za-z0-9+/=]{30,}", contentData):
            contentData, modificationFlag = decodeBase64(contentData, modificationFlag)

        # Decrypts SecureStrings - Changes STATE
        if "convertto-securestring" in contentData.lower() and \
                re.search("(?:[0-9]{1,3},){15,}[0-9]{1,3}", contentData.replace(" ", "")) and \
                re.search("[A-Za-z0-9+=/]{255,}", contentData):
            contentData, modificationFlag = decryptStrings(contentData, modificationFlag)


        # Normalize / De-Obfuscate the new contents before proceeding.
        contentData = normalize(contentData)

        if modificationFlag == None:
            break

        loopCount += 1

    return contentData


def main():

    parser = argparse.ArgumentParser(description="PowerShellProfiler analyzes PowerShell scripts statically to identify and score behaviors.")
    parser.add_argument("-f", "--file", help="PowerShell Script to behaviorally profile", metavar="<file_name>", required=True)
    parser.add_argument("-d", "--debug", help="Enables debug output", action="store_true")
    args = parser.parse_args()

    # Setup global debugFlag to print debug information throughout the script
    global debugFlag
    if args.debug:
        debugFlag = True
    else:
        debugFlag = None

    # Setup behaviorTags list so behaviors can be tracked throughout processing
    behaviorTags = []

    # Open file for processing, ignore errors
    scriptTime = datetime.now()
    with open(args.file, encoding='utf8', errors='ignore') as fh:
        originalData = fh.read()
    if debugFlag:
        print("Opened File %s" % (args.file))

    # Strip NULLs out before processing
    originalData = originalData.replace("\x00", "")

    # Launches the primary unraveling loop to begin cleaning up the script for profiling.
    startTime = datetime.now()
    alternativeData = "\n\n##### ORIGINAL SCRIPT #####\n\n%s\n\n##### ALTERED SCRIPT #####\n\n%s" %(originalData, unravelContent(originalData))
    stopTime = datetime.now() - startTime
    if debugFlag:
        print("\n\n##### TIMING / MATCH #####\n\nMain Processing: %s" % (stopTime))

    # Launches family specific profiling function over originalData and alternativeData
    startTime = datetime.now()
    family = family_finder(originalData + alternativeData)
    stopTime = datetime.now() - startTime
    if debugFlag:
        print("Family ID: %s" % (stopTime))

    # Launches behavioral profiling over originalData and alternativeData
    startTime = datetime.now()
    behaviorTags = profileBehaviors(behaviorTags, originalData, alternativeData, family)
    scriptTime = datetime.now() - scriptTime
    stopTime = datetime.now() - startTime
    if debugFlag:
        print("Behavior ID: %s" % (stopTime))

    # Score the behaviors and print final results
    score, verdict, behaviorTags = scoreBehaviors(behaviorTags)
    print("%s , %s , %s , %s , %s" % (args.file, score, verdict, scriptTime, "[" + " | ".join(behaviorTags) + "]"))

    # Print what we've parsed out for debugging
    if debugFlag:
        print(alternativeData)

    return


if __name__ == '__main__':
    main()
