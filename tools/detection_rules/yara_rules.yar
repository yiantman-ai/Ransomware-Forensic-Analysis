/*
   YARA Rules for Ransomware Detection
   Case: RANSOMWARE_21a34484
   Author: Jesse Antman
*/

rule Ransomware_Educational_PyInstaller
{
    meta:
        description = "Detects the educational ransomware compiled with PyInstaller"
        author = "Jesse Antman"
        date = "2026-02-15"
        reference = "https://github.com/yiantman-ai/Ransomware-Forensic-Analysis"
        severity = "critical"
        malware_family = "Educational Ransomware"
        
    strings:
        // PyInstaller indicators
        $pyinstaller1 = "PyInstaller" ascii
        $pyinstaller2 = "pyi-runtime-tmpdir" ascii
        
        // Python cryptography library
        $crypto1 = "cryptography.fernet" ascii
        $crypto2 = "Fernet" ascii
        $crypto3 = "from cryptography.fernet import" ascii
        
        // C2 communication strings
        $c2_1 = "/register" ascii
        $c2_2 = "/exfiltrate" ascii
        $c2_3 = "encryption_key" ascii
        $c2_4 = "victim_id" ascii
        
        // File encryption indicators
        $enc1 = ".locked" ascii
        $enc2 = "encrypted_files" ascii
        
        // Ransom note
        $ransom1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii
        $ransom2 = "README_DECRYPT.txt" ascii
        
        // Persistence
        $persist1 = "WindowsSecurityUpdate" ascii
        $persist2 = "MicrosoftEdgeUpdate" ascii
        
    condition:
        uint16(0) == 0x5A4D and // MZ header
        filesize < 20MB and
        (
            (2 of ($pyinstaller*)) and
            (2 of ($crypto*)) and
            (2 of ($c2_*)) and
            (1 of ($enc*)) and
            (1 of ($ransom*))
        )
}

rule Ransomware_C2_Traffic
{
    meta:
        description = "Detects C2 communication patterns in network traffic"
        author = "Jesse Antman"
        date = "2026-02-15"
        
    strings:
        $post_register = "POST /register" ascii
        $post_exfil = "POST /exfiltrate" ascii
        $json_key = "encryption_key" ascii
        $json_victim = "victim_id" ascii
        $json_files = "encrypted_files" ascii
        $content_type = "Content-Type: application/json" ascii
        
    condition:
        (
            ($post_register and $json_key and $json_victim) or
            ($post_exfil and $json_files)
        ) and $content_type
}

rule Ransomware_PowerShell_Loader
{
    meta:
        description = "Detects PowerShell loader script"
        author = "Jesse Antman"
        date = "2026-02-15"
        
    strings:
        $ps1 = "powershell" nocase
        $iex = "IEX" nocase
        $download = "DownloadString" nocase
        $webclient = "Net.WebClient" nocase
        $loader = "loader.ps1" nocase
        $config = "config.dat" nocase
        $base64 = "[Convert]::FromBase64String" nocase
        
    condition:
        3 of them
}
