/*
    SecuNik LogX - Suspicious Behavior Detection Rules
    Author: SecuNik LogX Team
    Date: 2024-01-01
    Description: Detection rules for suspicious but not definitively malicious patterns including anti-analysis, obfuscation, and persistence
*/

import "pe"
import "math"

// ============= ANTI-ANALYSIS TECHNIQUES =============

rule AntiAnalysis_VM_Detection : antianalysis suspicious
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects virtual machine detection attempts"
        severity = "medium"
        
    strings:
        // VMware detection
        $vmware1 = "VMware" ascii wide nocase
        $vmware2 = "vmtoolsd" ascii wide nocase
        $vmware3 = "VBOX" ascii wide nocase
        $vmware4 = { 56 4D 58 68 }  // VMXh
        
        // VirtualBox detection
        $vbox1 = "VirtualBox" ascii wide nocase
        $vbox2 = "VBoxService" ascii wide nocase
        $vbox3 = "VBoxTray" ascii wide nocase
        
        // Generic VM artifacts
        $vm_mac1 = "08:00:27" ascii  // VirtualBox MAC
        $vm_mac2 = "00:05:69" ascii  // VMware MAC
        $vm_mac3 = "00:0C:29" ascii  // VMware MAC
        $vm_mac4 = "00:1C:14" ascii  // VMware MAC
        $vm_mac5 = "00:50:56" ascii  // VMware MAC
        
        // CPUID checks
        $cpuid = { 0F A2 }  // CPUID instruction
        
        // Registry checks
        $reg1 = "HARDWARE\\Description\\System" ascii wide
        $reg2 = "SystemBiosVersion" ascii wide
        $reg3 = "HARDWARE\\ACPI\\DSDT\\VBOX__" ascii wide
        
    condition:
        (2 of ($vmware*) or 2 of ($vbox*)) or
        (any of ($vm_mac*) and $cpuid) or
        (2 of ($reg*))
}

rule AntiAnalysis_Debugger_Detection : antianalysis suspicious
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects debugger detection attempts"
        severity = "medium"
        
    strings:
        // API calls
        $api1 = "IsDebuggerPresent" ascii
        $api2 = "CheckRemoteDebuggerPresent" ascii
        $api3 = "NtQueryInformationProcess" ascii
        $api4 = "OutputDebugString" ascii
        $api5 = "ZwSetInformationThread" ascii
        
        // PEB checks
        $peb_check = { 64 A1 30 00 00 00 0F B6 40 02 }  // mov eax, fs:[30h]; movzx eax, byte [eax+2]
        
        // INT3 detection
        $int3_scan = { 80 3? CC }  // cmp byte [reg], 0xCC
        
        // Timing checks
        $rdtsc = { 0F 31 }  // RDTSC instruction
        $timing1 = "GetTickCount" ascii
        $timing2 = "QueryPerformanceCounter" ascii
        
        // Common debugger names
        $dbg1 = "ollydbg" nocase
        $dbg2 = "x64dbg" nocase
        $dbg3 = "windbg" nocase
        $dbg4 = "ida" nocase
        
    condition:
        (3 of ($api*)) or
        ($peb_check and $int3_scan) or
        ($rdtsc and any of ($timing*)) or
        (2 of ($dbg*))
}

rule AntiAnalysis_Sandbox_Evasion : antianalysis suspicious
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects sandbox evasion techniques"
        severity = "medium"
        
    strings:
        // Sleep/delay tactics
        $sleep1 = "Sleep" ascii
        $sleep2 = "WaitForSingleObject" ascii
        $delay = { 68 ?? ?? ?? ?? FF 15 }  // push large_value; call Sleep
        
        // User interaction checks
        $mouse1 = "GetCursorPos" ascii
        $mouse2 = "GetAsyncKeyState" ascii
        $mouse3 = "GetLastInputInfo" ascii
        
        // Environment checks
        $env1 = "SbieDll.dll" ascii  // Sandboxie
        $env2 = "dbghelp.dll" ascii
        $env3 = "api_log.dll" ascii
        $env4 = "dir_watch.dll" ascii
        
        // Process enumeration
        $proc1 = "CreateToolhelp32Snapshot" ascii
        $proc2 = "Process32First" ascii
        $proc3 = "Process32Next" ascii
        
        // File system checks
        $fs1 = "C:\\agent\\agent.pyw" ascii
        $fs2 = "C:\\sandbox" ascii
        $fs3 = "C:\\Sandbox" ascii
        
    condition:
        ($sleep1 and $delay) or
        (2 of ($mouse*)) or
        (any of ($env*)) or
        (all of ($proc*)) or
        (any of ($fs*))
}

// ============= OBFUSCATION PATTERNS =============

rule Obfuscation_String_Encryption : obfuscation suspicious
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects string encryption/obfuscation"
        severity = "medium"
        
    strings:
        // XOR loops
        $xor_loop1 = { 80 34 ?? ?? 4? 3? ?? ?? 7? }  // xor byte[reg+counter], key; inc counter; cmp counter, size; jl
        $xor_loop2 = { 31 ?? 83 ?? 04 39 ?? 7? }      // xor [reg], reg; add reg, 4; cmp reg, reg; jl
        
        // Base64 patterns
        $b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii
        $b64_decode = "FromBase64String" ascii
        
        // RC4 patterns
        $rc4_init = { 88 04 ?? 40 3D 00 01 00 00 7C }  // mov [reg+counter], al; inc eax; cmp eax, 256; jl
        
        // Custom encoding
        $custom_enc = { C1 ?? 04 80 ?? ?? 83 ?? ?? }   // shl/shr reg, 4; xor reg, key; and reg, mask
        
    condition:
        any of ($xor_loop*) or
        ($b64_chars and $b64_decode) or
        $rc4_init or
        #custom_enc > 5
}

rule Obfuscation_API_Hashing : obfuscation suspicious
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects API resolution by hash"
        severity = "medium"
        
    strings:
        // Common hashing algorithms
        $ror_hash = { C1 C? 0D }  // ror reg, 13
        $rol_hash = { C1 C? 07 }  // rol reg, 7
        $xor_add = { 33 ?? 03 }   // xor reg, reg; add
        
        // GetProcAddress patterns
        $gpa1 = { 8B ?? 3C 03 ?? 8B ?? ?? 78 }  // mov reg,[reg+3Ch]; add reg,reg; mov reg,[reg+78h]
        $gpa2 = "GetProcAddress" ascii
        
        // Hash comparison
        $cmp_hash = { 3B ?? 74 ?? E8 }  // cmp reg, reg; je; call
        
    condition:
        (any of ($ror_hash, $rol_hash) and $xor_add) or
        ($gpa1 and not $gpa2 and $cmp_hash)
}

rule Obfuscation_Control_Flow : obfuscation suspicious
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects control flow obfuscation"
        severity = "low"
        
    strings:
        // Opaque predicates
        $opaque1 = { 33 C0 74 ?? 75 ?? }  // xor eax, eax; je; jne (always jumps)
        $opaque2 = { 85 C0 74 ?? EB }     // test eax, eax; je; jmp
        
        // Jump chains
        $jmp_chain = { EB ?? EB ?? EB ?? EB }  // Multiple short jumps
        
        // Call/pop patterns
        $call_pop = { E8 00 00 00 00 5? }  // call $+5; pop reg
        
        // Conditional jumps to same target
        $jcc_same = { 7? ?? 7? ?? }  // jcc offset; jcc offset (same target)
        
    condition:
        any of ($opaque*) or
        #jmp_chain > 3 or
        #call_pop > 5 or
        $jcc_same
}

// ============= PERSISTENCE MECHANISMS =============

rule Persistence_Registry_Autorun : persistence suspicious
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects registry-based persistence"
        severity = "medium"
        
    strings:
        // Registry keys
        $run1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $run2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $run3 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii wide nocase
        $run4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii wide nocase
        
        // Registry APIs
        $api1 = "RegCreateKey" ascii
        $api2 = "RegSetValue" ascii
        $api3 = "RegOpenKey" ascii
        
        // Common persistence executable names
        $name1 = "svchost.exe" ascii wide
        $name2 = "rundll32.exe" ascii wide
        $name3 = "explorer.exe" ascii wide
        
    condition:
        (any of ($run*) and 2 of ($api*)) or
        (any of ($run*) and any of ($name*))
}

rule Persistence_Scheduled_Task : persistence suspicious
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects scheduled task creation"
        severity = "medium"
        
    strings:
        $schtasks = "schtasks" ascii wide nocase
        $create = "/create" ascii wide nocase
        $xml = "/xml" ascii wide nocase
        $tn = "/tn" ascii wide nocase
        $tr = "/tr" ascii wide nocase
        $sc = "/sc" ascii wide nocase
        
        $api1 = "ITaskScheduler" ascii
        $api2 = "ITaskFolder" ascii
        $api3 = "RegisterTaskDefinition" ascii
        
    condition:
        ($schtasks and $create) or
        (3 of ($/)) or
        (2 of ($api*))
}

rule Persistence_Service_Creation : persistence suspicious
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects service creation for persistence"
        severity = "medium"
        
    strings:
        $sc_exe = "sc.exe" ascii wide nocase
        $create = "create" ascii wide nocase
        $binpath = "binPath=" ascii wide nocase
        $start = "start=" ascii wide nocase
        
        $api1 = "CreateService" ascii
        $api2 = "OpenSCManager" ascii
        $api3 = "StartService" ascii
        $api4 = "ChangeServiceConfig" ascii
        
    condition:
        ($sc_exe and $create) or
        ($binpath and $start) or
        (3 of ($api*))
}

// ============= DATA EXFILTRATION =============

rule DataExfil_Archive_Creation : exfiltration suspicious
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects data archiving for exfiltration"
        severity = "medium"
        
    strings:
        // Archive tools
        $zip1 = "7z.exe" ascii wide nocase
        $zip2 = "rar.exe" ascii wide nocase
        $zip3 = "zip.exe" ascii wide nocase
        $zip4 = "tar.exe" ascii wide nocase
        
        // Archive parameters
        $param1 = "-p" ascii wide  // password
        $param2 = "-v" ascii wide  // volume
        $param3 = "-r" ascii wide  // recursive
        
        // Common data locations
        $data1 = "\\Desktop\\" ascii wide nocase
        $data2 = "\\Documents\\" ascii wide nocase
        $data3 = "\\Downloads\\" ascii wide nocase
        
    condition:
        (any of ($zip*) and 2 of ($param*)) or
        (any of ($zip*) and 2 of ($data*))
}

rule DataExfil_Network_Upload : exfiltration suspicious
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects network-based data exfiltration"
        severity = "high"
        
    strings:
        // Upload indicators
        $ftp1 = "ftp://" ascii wide nocase
        $ftp2 = "ftps://" ascii wide nocase
        $http_post = "POST" ascii
        $multipart = "multipart/form-data" ascii
        
        // Cloud storage
        $cloud1 = "dropbox.com" ascii wide nocase
        $cloud2 = "drive.google.com" ascii wide nocase
        $cloud3 = "onedrive.com" ascii wide nocase
        $cloud4 = "mega.nz" ascii wide nocase
        
        // Upload APIs
        $api1 = "InternetWriteFile" ascii
        $api2 = "HttpSendRequest" ascii
        $api3 = "WinHttpSendRequest" ascii
        
    condition:
        (any of ($ftp*) and any of ($api*)) or
        (any of ($cloud*) and $http_post) or
        ($http_post and $multipart)
}

// ============= CREDENTIAL DUMPING =============

rule CredentialDump_LSASS_Access : credentials suspicious
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects LSASS memory access for credential dumping"
        severity = "high"
        
    strings:
        $lsass1 = "lsass.exe" ascii wide nocase
        $lsass2 = "SamIConnect" ascii
        $lsass3 = "SamIGetPrivateData" ascii
        $lsass4 = "lsasrv.dll" ascii wide nocase
        
        $api1 = "OpenProcess" ascii
        $api2 = "ReadProcessMemory" ascii
        $api3 = "MiniDumpWriteDump" ascii
        $api4 = "NtQuerySystemInformation" ascii
        
        $privilege = "SeDebugPrivilege" ascii wide
        
    condition:
        (any of ($lsass*) and 2 of ($api*)) or
        ($api3 and $privilege)
}

rule CredentialDump_SAM_Registry : credentials suspicious
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects SAM registry access for credential dumping"
        severity = "high"
        
    strings:
        $sam1 = "\\SAM\\SAM" ascii wide nocase
        $sam2 = "\\SYSTEM\\CurrentControlSet\\Control\\Lsa" ascii wide nocase
        $sam3 = "\\SECURITY\\Policy\\Secrets" ascii wide nocase
        
        $reg1 = "reg save" ascii wide nocase
        $reg2 = "RegSaveKey" ascii
        $reg3 = "RegOpenKeyEx" ascii
        
        $shadow = "vssadmin" ascii wide nocase
        
    condition:
        (any of ($sam*) and any of ($reg*)) or
        ($shadow and any of ($sam*))
}

// ============= PROCESS INJECTION =============

rule ProcessInjection_Classic : injection suspicious
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects classic process injection techniques"
        severity = "high"
        
    strings:
        $api1 = "OpenProcess" ascii
        $api2 = "VirtualAllocEx" ascii
        $api3 = "WriteProcessMemory" ascii
        $api4 = "CreateRemoteThread" ascii
        $api5 = "NtCreateThreadEx" ascii
        $api6 = "RtlCreateUserThread" ascii
        
        $target1 = "explorer.exe" ascii wide nocase
        $target2 = "svchost.exe" ascii wide nocase
        $target3 = "notepad.exe" ascii wide nocase
        
    condition:
        (4 of ($api*)) or
        (3 of ($api*) and any of ($target*))
}

rule ProcessInjection_SetWindowsHook : injection suspicious
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects SetWindowsHook injection"
        severity = "medium"
        
    strings:
        $api1 = "SetWindowsHookEx" ascii
        $api2 = "CallNextHookEx" ascii
        $api3 = "UnhookWindowsHookEx" ascii
        
        $hook1 = { 00 0D 00 00 }  // WH_KEYBOARD_LL
        $hook2 = { 00 0E 00 00 }  // WH_MOUSE_LL
        
        $dll = { 4C 6F 61 64 4C 69 62 72 61 72 79 }  // LoadLibrary
        
    condition:
        (2 of ($api*)) or
        ($api1 and any of ($hook*)) or
        ($api1 and $dll)
}