# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.0] - 2026-02-16

### Initial Release

Complete forensic investigation of educational ransomware attack.

### Added

#### Documentation
- Comprehensive README with project overview
- Quick Start Guide for various user levels
- Investigation Methodology documentation
- Contributing guidelines
- MIT License
- This changelog

#### Reports
- Network Forensics Analysis (Phase 2)
- Memory Forensics Analysis (Phase 3)
- Final Investigation Report 
- MITRE ATT&CK mapping (25 techniques)

#### Evidence
- Network traffic capture (PCAP - 19MB, 4,634 packets)
- Memory dump (2.0GB with SHA256 verification)
- Sysmon event logs (13,459 events parsed)
- C2 server data (victim info, encryption key, file list)
- Complete evidence chain of custody

#### Analysis
- Complete attack timeline (90-second attack window)
- Network communication analysis
- Process execution chain
- File encryption analysis
- 24 IOCs extracted (Network, File, Registry, Process)

#### Malware
- Complete source code (350+ lines, fully commented)
- Deep malware analysis documentation
- Capability breakdown
- MITRE ATT&CK technique mapping per function

#### Tools
- **Decryption Tool** - Decrypt .locked files with key
- **IOC Scanner** - Automated compromise detection
- **Detection Rules**:
  - 7 Snort/Suricata rules
  - 5 Sigma rules (SIEM-agnostic)
  - 3 YARA rules (binary/traffic/loader)
- **Visualization Suite**:
  - Timeline graph generator
  - Attack phase breakdown
  - MITRE ATT&CK heatmap
  - Network flow diagram
- **Statistics Generator** - Comprehensive metrics report

#### Evidence Artifacts
- Registry exports (Run keys)
- Scheduled tasks export
- Process snapshots (before/after)
- Network snapshots (before/after)
- Encrypted file list
- Ransom note
- Evidence hash manifest

### Technical Details

**Attack Statistics:**
- Initial access: 12:49:38 UTC
- Malware execution: 12:50:51 UTC
- Data exfiltration: 12:51:06 UTC
- Total duration: 90 seconds
- Files encrypted: 37
- Encryption: AES-256 (Fernet)

**Forensic Coverage:**
- Sysmon events: 13,459 analyzed
- Network packets: 4,634 captured
- Processes analyzed: 121
- MITRE techniques: 25 identified
- IOCs extracted: 24

**Tools Used:**
- Volatility 3.28.0 (memory forensics)
- Wireshark 4.x (network analysis)
- Python-evtx (log parsing)
- WinPMEM 4.0-rc2 (memory acquisition)

### Infrastructure

**Development Environment:**
- Kali Linux 2024.x (analysis platform)
- Windows 10 Build 19041 (victim system)
- VMware Workstation (isolated network)

**Repository Stats:**
- Files: 80+
- Lines of code: 2,500+
- Lines of documentation: 3,000+
- Commits: 15+


---

**Maintainer:** Jesse Antman  
**Repository:** https://github.com/yiantman-ai/Ransomware-Forensic-Analysis  
**License:** MIT
