# Evidence Manifest

Complete inventory of forensic evidence collected during investigation.

**Case:** RANSOMWARE_21a34484  
**Date:** February 15-16, 2026  
**Investigator:** Jesse Antman  

---

## Chain of Custody

| Item | Collected | Hash (SHA256) | Location | Status |
|------|-----------|---------------|----------|--------|
| Memory Dump | 2026-02-15 14:10:04 | bbddae76c5d688f8325eb5227bc259e87033e8233aeb032291f8e01f80e72079 | External storage | Verified |
| PCAP | 2026-02-15 12:48-12:54 | 174d6a5d08dcabb1295002fb99fcac68fcab47064c40e0ca6943c9ef3661338e | pcap/attack_full.pcap | Verified |
| Sysmon Log | 2026-02-15 15:42 | N/A | Extracted | Verified |
| C2 Logs | 2026-02-15 12:50-12:51 | N/A | logs/ | Verified |

---

## Evidence Items

### 1. Volatile Evidence

#### Memory Dump
- **File:** memory_dump_final.raw
- **Size:** 2.0 GB
- **Format:** Raw physical memory
- **Tool:** WinPMEM 4.0-rc2
- **Hash:** bbddae76c5d688f8325eb5227bc259e87033e8233aeb032291f8e01f80e72079
- **Contains:**
  - Process memory (121 processes)
  - Network connections
  - Registry in memory
  - Loaded DLLs
  - Command lines

### 2. Network Evidence

#### PCAP File
- **File:** attack_full.pcap
- **Size:** 19 MB
- **Packets:** 4,634
- **Duration:** 285 seconds
- **Tool:** tcpdump
- **Hash:** 174d6a5d08dcabb1295002fb99fcac68fcab47064c40e0ca6943c9ef3661338e
- **Contains:**
  - Phishing page access
  - Payload downloads
  - C2 communication
  - Data exfiltration

### 3. Event Logs

#### Sysmon
- **File:** Sysmon.evtx
- **Size:** 17 MB
- **Events:** 13,459 total
  - Process Creates: 3,048
  - Network Connects: 512
  - File Creates: 4,115
  - Registry Events: 5,784

#### Security
- **File:** Security.evtx
- **Size:** 12 MB
- **Events:** Authentication, privilege use

#### System
- **File:** System.evtx
- **Size:** 1.1 MB
- **Events:** Service starts, system events

### 4. Registry Evidence

- **SAM:** User account database
- **SECURITY:** Security policy
- **SOFTWARE:** Installed applications
- **SYSTEM:** System configuration
- **Run Keys:** Exported persistence entries

### 5. File System Evidence

- **Encrypted Files:** List of 37 .locked files
- **Ransom Note:** README_DECRYPT.txt
- **Process Snapshots:** Before/after comparison
- **Network Snapshots:** Connection states

### 6. C2 Server Data

#### Exfiltrated Data
- **21a34484_info.json:**
  - System information
  - Encryption key
  - Stolen credentials (empty)
  - Browser history (15 entries)

- **21a34484_files.json:**
  - List of 37 encrypted files
  - File paths
  - Timestamps

- **21a34484_key.txt:**
  - Encryption key (CRITICAL)
  - Victim ID

#### Server Logs
- **c2_20260215.json:**
  - All C2 requests
  - Timestamps
  - Response codes

---

## Evidence Processing

### Acquisition Methods

1. **Memory:**
   - Live acquisition with WinPMEM
   - No shutdown before capture
   - Hash calculated immediately

2. **Network:**
   - tcpdump on mirror port
   - Full packet capture
   - No filtering applied

3. **Logs:**
   - Copied from live system
   - Verified with hash
   - Original timestamps preserved

4. **Registry:**
   - Exported with reg.exe
   - Complete hives copied
   - Offline analysis

### Verification

All evidence verified with:
- SHA256 hashing
- File integrity checks
- Chain of custody logs
- Dual witness verification

### Storage

- **Original Evidence:** Secure offline storage
- **Working Copies:** Analysis environment
- **Backups:** Geographic redundancy
- **Access:** Logged and restricted

---

## Analysis Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| Volatility | 3.28.0 | Memory analysis |
| Wireshark | 4.x | PCAP analysis |
| tshark | 4.x | Command-line packet analysis |
| Python-evtx | 0.7.0 | Event log parsing |
| WinPMEM | 4.0-rc2 | Memory acquisition |
| reg.exe | Built-in | Registry export |
| tcpdump | 4.99.x | Network capture |

---

## Integrity Verification
```bash
# Verify all evidence
sha256sum -c evidence_hashes.txt

# Expected output:
# memory_dump_final.raw: OK
# attack_full.pcap: OK
# [all files verified]
```

---

## Legal Compliance

- Evidence handling follows NIST SP 800-86
- Chain of custody maintained
- No evidence tampering
- All access logged
- Original evidence preserved

---

## Notes

- All timestamps in UTC
- File paths use Windows format (C:\...)
- Evidence suitable for legal proceedings
- Analysis conducted on isolated systems
- No evidence was altered during analysis

---

**Custodian:** Jesse Antman  
**Date:** February 16, 2026  
**Status:** ✅ Complete and Verified
