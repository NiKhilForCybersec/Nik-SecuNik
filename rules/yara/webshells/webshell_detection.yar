/*
    SecuNik LogX - Webshell Detection Rules
    Author: SecuNik LogX Team
    Date: 2024-01-01
    Description: Detection rules for various webshell variants including PHP, ASP/ASPX, JSP, and encoded shells
*/

// ============= PHP WEBSHELLS =============

rule Webshell_PHP_c99_Shell : webshell php
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects c99 PHP webshell and variants"
        reference = "https://github.com/tennc/webshell"
        severity = "critical"
        
    strings:
        $c99_1 = "c99shell" nocase
        $c99_2 = "C99Shell" nocase
        $c99_3 = "!C99Shell v." nocase
        $c99_4 = "c99_buff_prepare" nocase
        $c99_5 = "c99_sess_put" nocase
        $auth = "md5($_POST[\"pass\"])" nocase
        $system = "system($_POST['cmd'])" nocase
        
    condition:
        any of ($c99_*) or 
        ($auth and $system)
}

rule Webshell_PHP_r57_Shell : webshell php
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects r57 PHP webshell"
        severity = "critical"
        
    strings:
        $r57_1 = "r57shell" nocase
        $r57_2 = "r57 shell" nocase
        $r57_3 = "R57 Shell" nocase
        $r57_4 = "r57_tbl_files" nocase
        $r57_5 = "r57_lang" nocase
        $r57_6 = "r57pas" nocase
        $func = "r57_processeslist" nocase
        
    condition:
        any of ($r57_*) or $func
}

rule Webshell_PHP_Generic_Functions : webshell php suspicious
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects generic PHP webshell functions"
        severity = "high"
        
    strings:
        // Command execution
        $exec1 = "eval(" nocase
        $exec2 = "assert(" nocase
        $exec3 = "system(" nocase
        $exec4 = "exec(" nocase
        $exec5 = "shell_exec(" nocase
        $exec6 = "passthru(" nocase
        $exec7 = "proc_open(" nocase
        $exec8 = "popen(" nocase
        
        // File operations
        $file1 = "file_get_contents(" nocase
        $file2 = "file_put_contents(" nocase
        $file3 = "fwrite(" nocase
        
        // Encoding/Decoding
        $enc1 = "base64_decode(" nocase
        $enc2 = "str_rot13(" nocase
        $enc3 = "gzinflate(" nocase
        $enc4 = "gzuncompress(" nocase
        
        // Network
        $net1 = "fsockopen(" nocase
        $net2 = "curl_exec(" nocase
        
        // Input handling
        $input1 = "$_POST[" nocase
        $input2 = "$_GET[" nocase
        $input3 = "$_REQUEST[" nocase
        $input4 = "$_COOKIE[" nocase
        
    condition:
        (3 of ($exec*) and any of ($input*)) or
        (any of ($exec*) and any of ($enc*) and any of ($input*)) or
        (any of ($exec*) and any of ($file*) and any of ($net*))
}

rule Webshell_PHP_Obfuscated : webshell php obfuscated
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects obfuscated PHP webshells"
        severity = "high"
        
    strings:
        // Obfuscation patterns
        $obf1 = /\$[a-z0-9]{1,2} = '[a-zA-Z0-9+\/]{500,}'/
        $obf2 = /\$[a-z0-9]{1,2} = str_replace\(/
        $obf3 = "chr(" nocase
        $obf4 = /\$[a-z0-9_]+ = \$[a-z0-9_]+\(\$[a-z0-9_]+\(/
        
        // Encoded eval
        $eval1 = /eval\s*\(\s*base64_decode/
        $eval2 = /eval\s*\(\s*gzinflate/
        $eval3 = /eval\s*\(\s*str_rot13/
        $eval4 = /eval\s*\(\s*\$[a-z0-9_]+\s*\(/
        
        // Variable functions
        $varfunc = /\$[a-z0-9_]+\s*=\s*['"](system|exec|shell_exec|passthru|eval|assert)['"]/
        
    condition:
        (2 of ($obf*) and any of ($eval*)) or
        ($varfunc and any of ($obf*))
}

rule Webshell_PHP_b374k : webshell php
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects b374k PHP webshell"
        severity = "critical"
        
    strings:
        $b374k_1 = "b374k" nocase
        $b374k_2 = "b374k shell" nocase
        $b374k_3 = "\"b374k\"" nocase
        $b374k_4 = "$s_name = \"b374k\"" nocase
        $func = "\"explorer\",\"terminal\",\"eval\"" nocase
        
    condition:
        any of ($b374k_*) or $func
}

// ============= ASP/ASPX WEBSHELLS =============

rule Webshell_ASPX_Generic : webshell aspx
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects generic ASPX webshells"
        severity = "high"
        
    strings:
        // Command execution
        $exec1 = "Process.Start" nocase
        $exec2 = "ProcessStartInfo" nocase
        $exec3 = "System.Diagnostics" nocase
        $exec4 = "cmd.exe" nocase
        
        // File operations
        $file1 = "System.IO.File" nocase
        $file2 = "StreamWriter" nocase
        $file3 = "FileStream" nocase
        
        // Network
        $net1 = "System.Net.WebClient" nocase
        $net2 = "DownloadString" nocase
        $net3 = "DownloadFile" nocase
        
        // Input
        $input1 = "Request.Form" nocase
        $input2 = "Request.QueryString" nocase
        $input3 = "Request[" nocase
        
        // Eval patterns
        $eval1 = "eval(Request" nocase
        $eval2 = "Execute(Request" nocase
        
    condition:
        (any of ($exec*) and any of ($input*)) or
        (any of ($file*) and any of ($net*)) or
        any of ($eval*)
}

rule Webshell_ASPX_ASPXSPY : webshell aspx
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects ASPXSpy webshell"
        severity = "critical"
        
    strings:
        $aspxspy1 = "ASPXSpy" nocase
        $aspxspy2 = "ASPXSpy2" nocase
        $aspxspy3 = "CmdShell" nocase
        $aspxspy4 = "WScript.Shell" nocase
        $auth = "if(password==yourpass)" nocase
        
    condition:
        any of ($aspxspy*) or
        ($auth and $aspxspy4)
}

rule Webshell_ASP_Generic : webshell asp
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects generic ASP webshells"
        severity = "high"
        
    strings:
        // Objects
        $obj1 = "CreateObject(\"WScript.Shell\")" nocase
        $obj2 = "CreateObject(\"Scripting.FileSystemObject\")" nocase
        $obj3 = "CreateObject(\"ADODB.Stream\")" nocase
        
        // Execution
        $exec1 = ".Run" nocase
        $exec2 = ".Exec" nocase
        $exec3 = "eval(" nocase
        $exec4 = "execute(" nocase
        
        // Input
        $input1 = "Request.Form" nocase
        $input2 = "Request.QueryString" nocase
        $input3 = "Request(\"" nocase
        
    condition:
        (any of ($obj*) and any of ($exec*)) or
        (any of ($obj*) and any of ($input*))
}

// ============= JSP WEBSHELLS =============

rule Webshell_JSP_Generic : webshell jsp
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects generic JSP webshells"
        severity = "high"
        
    strings:
        // Imports
        $import1 = "import=\"java.io.*\"" nocase
        $import2 = "import=\"java.util.*\"" nocase
        $import3 = "import=\"java.lang.*\"" nocase
        
        // Execution
        $exec1 = "Runtime.getRuntime().exec" nocase
        $exec2 = "ProcessBuilder" nocase
        $exec3 = ".exec(request.getParameter" nocase
        
        // File operations
        $file1 = "FileOutputStream" nocase
        $file2 = "FileInputStream" nocase
        $file3 = "File(" nocase
        
        // Input
        $input1 = "request.getParameter" nocase
        $input2 = "request.getInputStream" nocase
        
    condition:
        (any of ($import*) and any of ($exec*)) or
        (any of ($exec*) and any of ($input*)) or
        (2 of ($file*) and any of ($input*))
}

rule Webshell_JSP_JspSpy : webshell jsp
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects JspSpy webshell"
        severity = "critical"
        
    strings:
        $spy1 = "JspSpy" nocase
        $spy2 = "jsp-reverse" nocase
        $spy3 = "o=exec&cmd=" nocase
        $auth = "pwd.equals(password)" nocase
        
    condition:
        any of ($spy*) or $auth
}

// ============= PERL/CGI WEBSHELLS =============

rule Webshell_Perl_CGI : webshell perl
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects Perl/CGI webshells"
        severity = "high"
        
    strings:
        $shebang = "#!/usr/bin/perl" nocase
        $cgi = "use CGI" nocase
        
        // Execution
        $exec1 = "system(" nocase
        $exec2 = "exec(" nocase
        $exec3 = "`$cmd`" nocase
        $exec4 = "open(" nocase
        
        // Input
        $input1 = "param(" nocase
        $input2 = "$ENV{" nocase
        $input3 = "$cgi->param" nocase
        
    condition:
        $shebang and (
            (any of ($exec*) and any of ($input*)) or
            ($cgi and any of ($exec*))
        )
}

// ============= PYTHON WEBSHELLS =============

rule Webshell_Python_Generic : webshell python
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects Python webshells"
        severity = "high"
        
    strings:
        $shebang = "#!/usr/bin/python" nocase
        
        // Imports
        $import1 = "import os" nocase
        $import2 = "import subprocess" nocase
        $import3 = "import socket" nocase
        
        // Execution
        $exec1 = "os.system(" nocase
        $exec2 = "subprocess.call(" nocase
        $exec3 = "subprocess.Popen(" nocase
        $exec4 = "eval(" nocase
        $exec5 = "exec(" nocase
        
        // Web frameworks
        $web1 = "flask" nocase
        $web2 = "django" nocase
        $web3 = "cgi" nocase
        
    condition:
        (any of ($import*) and any of ($exec*)) or
        (any of ($web*) and any of ($exec*))
}

// ============= ENCODED/OBFUSCATED WEBSHELLS =============

rule Webshell_Base64_Encoded : webshell obfuscated
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects base64 encoded webshells"
        severity = "high"
        
    strings:
        // Base64 patterns for common webshell strings
        $b64_eval = "ZXZhbA==" // eval
        $b64_system = "c3lzdGVt" // system
        $b64_exec = "ZXhlYw==" // exec
        $b64_cmd = "Y21k" // cmd
        $b64_shell = "c2hlbGw=" // shell
        
        // Large base64 blocks
        $large_b64 = /[a-zA-Z0-9+\/]{200,}={0,2}/
        
        // Decode functions
        $decode1 = "base64_decode" nocase
        $decode2 = "Convert.FromBase64String" nocase
        $decode3 = "atob(" nocase
        
    condition:
        (any of ($b64_*) and any of ($decode*)) or
        ($large_b64 and any of ($decode*))
}

rule Webshell_Hex_Encoded : webshell obfuscated
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects hex encoded webshells"
        severity = "high"
        
    strings:
        // Hex patterns
        $hex_pattern = /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/
        $hex_string = /[0-9a-f]{100,}/
        
        // Decode functions
        $decode1 = "unhex" nocase
        $decode2 = "hex2bin" nocase
        $decode3 = "pack(" nocase
        $decode4 = "chr(" nocase
        
    condition:
        ($hex_pattern and any of ($decode*)) or
        ($hex_string and 2 of ($decode*))
}

rule Webshell_Unicode_Obfuscated : webshell obfuscated
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects unicode obfuscated webshells"
        severity = "medium"
        
    strings:
        // Unicode patterns
        $uni1 = /\\u[0-9a-f]{4}/
        $uni2 = /&#[0-9]{2,5};/
        $uni3 = /&#x[0-9a-f]{2,4};/
        
        // Suspicious unicode
        $sus_uni1 = "\\u0065\\u0076\\u0061\\u006c" // eval
        $sus_uni2 = "\\u0073\\u0079\\u0073\\u0074\\u0065\\u006d" // system
        
    condition:
        (#uni1 > 10) or
        (#uni2 > 10) or
        (#uni3 > 10) or
        any of ($sus_uni*)
}

// ============= SPECIFIC WEBSHELL FAMILIES =============

rule Webshell_ChinaChopper : webshell
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects China Chopper webshell"
        severity = "critical"
        
    strings:
        $china1 = "eval($_POST[" nocase
        $china2 = "eval($_GET[" nocase
        $china3 = "eval($_REQUEST[" nocase
        $china4 = "assert($_POST[" nocase
        $china5 = "assert($_GET[" nocase
        $china6 = "assert($_REQUEST[" nocase
        
        // Small file size pattern
        $small = /^.{0,200}$/s
        
    condition:
        any of ($china*) and filesize < 500
}

rule Webshell_WSO : webshell php
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects WSO (Web Shell by Orb) webshell"
        severity = "critical"
        
    strings:
        $wso1 = "WSO" nocase
        $wso2 = "Web Shell by oRb" nocase
        $wso3 = "wsoSecParam" nocase
        $wso4 = "wsoLogin" nocase
        $wso5 = "makeLogin" nocase
        
    condition:
        any of them
}

rule Webshell_Weevely : webshell php
{
    meta:
        author = "SecuNik LogX"
        date = "2024-01-01"
        description = "Detects Weevely webshell"
        severity = "critical"
        
    strings:
        $weevely1 = "weevely" nocase
        $weevely2 = "Weevely" nocase
        $pattern = /\$[a-z0-9]+=\$[a-z0-9]+\(\$[a-z0-9]+,\s*\$[a-z0-9]+\(\$[a-z0-9]+\)\);/
        
    condition:
        any of ($weevely*) or
        (#pattern > 5)
}