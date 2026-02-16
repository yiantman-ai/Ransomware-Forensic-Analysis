# Ransomware Forensic Analysis Project

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Volatility 3](https://img.shields.io/badge/Volatility-3.28.0-red.svg)](https://github.com/volatilityfoundation/volatility3)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange.svg)](https://attack.mitre.org/)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/yiantman-ai/Ransomware-Forensic-Analysis/graphs/commit-activity)

**Complete digital forensic investigation: Ransomware attack analysis with Network, Memory, and Log forensics**

🎓 **Educational Project** | 🔒 **For Training Only** | 🔍 **Full Analysis Included**

---
# Ransomware Forensic Analysis Project

**Case ID:** RANSOMWARE_21a34484  
**Investigation Date:** February 2026  
**Status:** Complete  

---

## Executive Summary

Advanced ransomware attack targeting a Windows 10 environment, resulting in encryption of 37 files using AES-256 (Fernet). The attack was delivered via social engineering (fake Facebook page) and included:

- Multi-file encryption (PDF, DOCX, XLSX, TXT, JPG)
- C2 communication over HTTP
- Credential theft attempts (Chrome/Firefox)
- Dual persistence mechanisms
- Data exfiltration

**Attack Duration:** 90 seconds (from initial payload download to exfiltration)

---

## Key Findings

| Category | Finding |
|----------|---------|
| **Victim ID** | 21a34484 |
| **Files Encrypted** | 37 files |
| **Encryption** | AES-256 (Fernet) |
| **C2 Server** | 192.168.74.147:8080 |
| **Attack Vector** | Social Engineering (Phishing) |
| **Persistence** | Registry Run Key + Scheduled Task |
| **Data Exfiltrated** | System info, encryption key, file list, browser history |

---

## Repository Structure
```
.
├── README.md                          # This file
├── reports/
│   ├── 01_Network_Forensics.md        # Network traffic analysis
│   ├── 02_Memory_Forensics.md         # Volatility analysis
│   ├── 03_Log_Analysis.md             # Sysmon & event logs
│   ├── 04_Timeline_Analysis.md        # Complete attack timeline
│   └── 05_Final_Report.md             # Executive summary
├── analysis/
│   ├── network/                       # PCAP analysis results
│   ├── memory/                        # Volatility outputs
│   ├── logs/                          # Log analysis
│   ├── timeline/                      # Timeline data
│   └── iocs/                          # IOCs extracted
├── evidence/
│   ├── 21a34484_info.json            # Victim information
│   ├── 21a34484_files.json           # Encrypted file list
│   └── 21a34484_key.txt              # Encryption key
├── logs/                              # C2 server logs
└── docs/
    ├── Methodology.md                 # Investigation approach
    ├── Tools.md                       # Tools documentation
    └── MITRE_ATT&CK.md               # Technique mapping
```

---

## Investigation Phases

### Phase 1: Evidence Acquisition 
- Memory dump acquisition (2.0GB)
- Network traffic capture (PCAP)
- Event log collection (Sysmon, Security, System)
- Registry hive extraction
- File system metadata

### Phase 2: Network Forensics 
- PCAP analysis (4,634 packets)
- HTTP traffic reconstruction
- C2 communication mapping
- Timeline creation
- IOC extraction

### Phase 3: Memory Forensics 
- Process analysis (Volatility 3)
- Network connection enumeration
- DLL injection detection
- Command line extraction
- Code injection analysis

### Phase 4: Log Analysis 
- Sysmon event correlation
- Security event review
- Registry change tracking
- File creation timeline
- Process execution chain

### Phase 5: Timeline Reconstruction 
- Super timeline creation
- Event correlation across sources
- Attack sequence mapping
- MITRE ATT&CK technique mapping

### Phase 6: Reporting 
- Technical findings documentation
- IOC compilation
- Remediation recommendations
- Executive summary

---

## Tools & Techniques

### Forensic Tools

| Tool | Purpose |
|------|---------|
| **Volatility 3** | Memory forensics & process analysis |
| **Wireshark/tshark** | Network traffic analysis |
| **Sysmon** | Windows event logging |
| **WinPMEM** | Memory acquisition |
| **MFTECmd** | Master File Table parsing |
| **EvtxECmd** | Event log parsing |
| **Registry Explorer** | Registry forensics |

### Analysis Techniques

- Network traffic analysis (packet inspection, protocol analysis)
- Memory forensics (process listing, network connections, malfind)
- Log correlation (Sysmon, Security, System logs)
- Timeline analysis (super timeline from multiple sources)
- MITRE ATT&CK mapping (technique identification)

---

## Attack Flow
```
┌─────────────────────────────────────────────────────────────┐
│                      ATTACK SEQUENCE                        │
└─────────────────────────────────────────────────────────────┘

1. Initial Access
   └─> User visits fake Facebook page (192.168.74.147:8080)
   
2. Execution
   └─> User copies & runs PowerShell command
   └─> loader.ps1 downloaded (868 bytes)
   └─> config.dat downloaded (18.6MB encoded payload)
   
3. Persistence
   └─> Registry Run Key created
   └─> Scheduled Task created
   
4. Discovery
   └─> System information gathered
   └─> File enumeration (Documents, Pictures)
   
5. Credential Access
   └─> Chrome password theft attempted
   └─> Firefox password theft attempted
   └─> Browser history stolen
   
6. Collection
   └─> 37 files targeted for encryption
   
7. Command & Control
   └─> POST /register (system info + encryption key)
   
8. Exfiltration
   └─> POST /exfiltrate (file list + metadata)
   
9. Impact
   └─> AES-256 encryption applied
   └─> Files renamed with .locked extension
   └─> Ransom note dropped on desktop
```

---

## Indicators of Compromise (IOCs)

### Network
```
IP Address:   192.168.74.147
Port:         8080
Protocol:     HTTP
```

### URLs
```
http://192.168.74.147:8080/
http://192.168.74.147:8080/loader.ps1
http://192.168.74.147:8080/config.dat
http://192.168.74.147:8080/register
http://192.168.74.147:8080/exfiltrate
```

### File Hashes
```
SHA256 (memory_dump_final.raw):
bbddae76c5d688f8325eb5227bc259e87033e8233aeb032291f8e01f80e72079

SHA256 (attack_full.pcap):
174d6a5d08dcabb1295002fb99fcac68fcab47064c40e0ca6943c9ef3661338e
```

### Registry
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsSecurityUpdate
```

### Scheduled Task
```
Task Name: MicrosoftEdgeUpdate
Trigger:   At logon
Action:    Execute ransomware binary
```

### File Extensions
```
Original: .pdf, .docx, .xlsx, .txt, .jpg
Encrypted: .locked
```

---

## MITRE ATT&CK Techniques

| Tactic | Technique ID | Technique Name | Evidence Location |
|--------|--------------|----------------|-------------------|
| **Initial Access** | T1566.002 | Phishing: Spearphishing Link | PCAP, browser history |
| **Execution** | T1059.001 | PowerShell | Sysmon Event 1, memory |
| **Execution** | T1204.002 | User Execution: Malicious File | Process creation logs |
| **Persistence** | T1547.001 | Registry Run Keys | Registry hive, Sysmon Event 13 |
| **Persistence** | T1053.005 | Scheduled Task | Scheduled task export |
| **Defense Evasion** | T1140 | Deobfuscate/Decode Files | PCAP (Base64 payload) |
| **Defense Evasion** | T1070.004 | File Deletion | MFT analysis |
| **Credential Access** | T1555.003 | Web Browser Credentials | C2 exfiltrated data |
| **Discovery** | T1082 | System Information Discovery | C2 registration data |
| **Discovery** | T1083 | File and Directory Discovery | File enumeration in logs |
| **Collection** | T1005 | Data from Local System | Encrypted file list |
| **Command & Control** | T1071.001 | Web Protocols | HTTP traffic to C2 |
| **Command & Control** | T1132.001 | Standard Encoding | Base64 encoded payload |
| **Exfiltration** | T1041 | Exfiltration Over C2 | POST requests to C2 |
| **Impact** | T1486 | Data Encrypted for Impact | 37 .locked files |

[Complete mapping: docs/MITRE_ATT&CK.md]

---

## Critical Information

**Encryption Key Location:**  
`evidence/21a34484_key.txt`

**Key Value:**  
```
9Wf1-APAw9C2sLDinvPOJGvWEop9a5C3d4nP8OAa7qw=
```

This key is the **ONLY** way to decrypt the 37 encrypted files. It was exfiltrated to the C2 server during the attack and stored in `~/ransomware_c2/encryption_keys/21a34484_key.txt`.

---

## Recommendations

### Immediate Actions

1. **Network Segmentation**
   - Isolate critical systems
   - Implement strict egress filtering
   - Block connections to non-approved external IPs

2. **Enhanced Monitoring**
   - Deploy EDR solution
   - Enable Sysmon on all endpoints
   - Implement SIEM with correlation rules

3. **User Training**
   - Phishing awareness training
   - Social engineering simulations
   - Incident reporting procedures

### Technical Controls

1. **Email Security**
   - Implement DMARC/SPF/DKIM
   - URL rewriting and sandboxing
   - Advanced threat protection

2. **Endpoint Protection**
   - Application whitelisting
   - Disable PowerShell for standard users
   - Enable tamper protection on AV

3. **Network Security**
   - Implement IDS/IPS with C2 detection
   - SSL/TLS inspection for outbound traffic
   - DNS filtering and logging

4. **Backup Strategy**
   - Offline/immutable backups
   - Regular backup testing
   - Rapid recovery procedures

### Detection Rules

**Snort/Suricata:**
```
alert http any any -> any any (msg:"Possible C2 POST /register"; 
  content:"POST"; http_method; content:"/register"; http_uri; 
  content:"encryption_key"; http_client_body; sid:1000001;)

alert http any any -> any any (msg:"Large PowerShell Script Download"; 
  content:".ps1"; http_uri; sid:1000002;)

alert http any any -> any any (msg:"Large Encoded Payload Download"; 
  content:".dat"; http_uri; threshold:type threshold, 
  track by_src, count 1, seconds 60; sid:1000003;)
```

---

## Lessons Learned

### What Worked

- **Sysmon logging** provided detailed process and network event data
- **Memory acquisition** captured running malware before system reboot
- **PCAP capture** revealed complete C2 communication
- **Quick response** preserved volatile evidence

### What Could Be Improved

- **Email gateway** would have blocked phishing page access
- **Application whitelisting** would prevent unsigned executable
- **Egress filtering** would block C2 communication
- **User awareness** would identify fake Facebook page

### Key Takeaways

1. **Multiple layers of defense** are essential (defense in depth)
2. **Logging is critical** - without Sysmon, investigation would be limited
3. **Network monitoring** catches C2 communication patterns
4. **User training** is the first line of defense
5. **Rapid response** preserves forensic evidence

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
- [Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

## Legal Notice

**FOR EDUCATIONAL PURPOSES ONLY**

This project is part of a controlled forensic training exercise. All activities were performed in an isolated lab environment with no real victims or damage.

- All malware samples are educational simulations
- No real data was compromised
- All systems involved are dedicated training VMs
- Network traffic was contained within isolated virtual network

This documentation is shared for educational and training purposes only.

---

## Author

**Forensic Analyst:** Jesse Antman  
**GitHub:** https://github.com/yiantman-ai  
**Email:** yi.Antman@gmail.com  
**Repository:** https://github.com/yiantman-ai/Ransomware-Forensic-Analysis

---

## Project Status

- [x] Evidence acquisition complete
- [x] Network forensics complete
- [x] Memory forensics complete
- [x] Log analysis complete
- [x] Timeline reconstruction complete
- [x] MITRE ATT&CK mapping complete
- [x] Final report complete

**Last Updated:** February 2026

