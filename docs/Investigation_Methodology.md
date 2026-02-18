# Digital Forensic Investigation Methodology

**Case:** RANSOMWARE_21a34484  
**Date:** February 2026  

---

## Investigation Framework

This investigation follows the NIST Cybersecurity Framework and SANS DFIR methodology.

### Phase 1: Preparation

**Objective:** Establish investigation capability

**Activities:**
- Set up isolated lab environment
- Configure forensic workstation (Kali Linux)
- Install forensic tools (Volatility, Wireshark, etc.)
- Document baseline configurations

**Deliverables:**
- Lab environment documentation
- Tool inventory
- Chain of custody forms

---

### Phase 2: Identification

**Objective:** Detect and scope the incident

**Activities:**
- Initial triage of affected system
- Identify indicators of compromise
- Determine attack vector
- Assess impact scope

**Deliverables:**
- Incident summary
- Initial IOC list
- Affected systems inventory

---

### Phase 3: Collection

**Objective:** Acquire forensic evidence

**Activities:**
- Memory dump acquisition (WinPMEM)
- Network traffic capture (tcpdump)
- Event log collection (Sysmon, Security, System)
- Registry hive extraction
- File system metadata collection

**Tools Used:**
- WinPMEM 4.0-rc2 (memory)
- tcpdump (network)
- Windows Event Viewer (logs)
- reg.exe (registry)

**Deliverables:**
- Memory dump (2.0 GB)
- PCAP file (19 MB)
- Event logs (30+ MB)
- Registry hives
- Evidence hash list

---

### Phase 4: Examination

**Objective:** Process and analyze evidence

**Activities:**

#### Network Forensics
- PCAP analysis with Wireshark/tshark
- HTTP traffic reconstruction
- C2 communication identification
- Timeline creation

#### Memory Forensics
- Process list analysis (Volatility pslist)
- Network connections (Volatility netscan)
- Command line extraction (Volatility cmdline)
- Malware detection (Volatility malfind)

#### Log Analysis
- Sysmon event parsing
- Event correlation
- Process execution chain
- File/Registry modifications

**Tools Used:**
- Volatility 3.28.0
- Wireshark 4.x
- tshark
- Python-evtx
- Custom parsing scripts

**Deliverables:**
- Network analysis report
- Memory forensics report
- Log analysis results
- Process execution timeline

---

### Phase 5: Analysis

**Objective:** Draw conclusions from evidence

**Activities:**
- Timeline reconstruction
- Attack chain mapping
- MITRE ATT&CK technique identification
- IOC extraction
- Root cause analysis

**Deliverables:**
- Super timeline (all sources)
- MITRE ATT&CK mapping (25 techniques)
- IOC list (24 indicators)
- Attack flow diagram

---

### Phase 6: Presentation

**Objective:** Communicate findings

**Activities:**
- Technical report writing
- Executive summary creation
- Visual aids preparation
- Recommendations development

**Deliverables:**
- Final report (50+ pages)
- Executive summary
- Timeline visualizations
- Detection rules
- Remediation guide

---

## Evidence Handling

### Chain of Custody

All evidence follows strict chain of custody:

1. **Acquisition**
   - Time/date stamp
   - Collector identification
   - Hash calculation (SHA256)

2. **Transfer**
   - Secure transport
   - Transfer log
   - Hash verification

3. **Analysis**
   - Read-only access
   - Working copies
   - Original preservation

4. **Storage**
   - Secure location
   - Access controls
   - Integrity monitoring

### Integrity Verification

All evidence files verified with SHA256:
```bash
sha256sum evidence_file.raw > evidence.sha256
sha256sum -c evidence.sha256
```

---

## Tools & Techniques

### Memory Forensics (Volatility 3)
```bash
# System info
vol3 -f memory.raw windows.info

# Process list
vol3 -f memory.raw windows.pslist

# Network connections
vol3 -f memory.raw windows.netscan

# Command lines
vol3 -f memory.raw windows.cmdline

# Malware detection
vol3 -f memory.raw windows.malfind
```

### Network Analysis (Wireshark/tshark)
```bash
# Statistics
capinfos capture.pcap

# HTTP requests
tshark -r capture.pcap -Y "http.request"

# Extract objects
wireshark capture.pcap → File → Export Objects → HTTP
```

### Log Analysis (Sysmon)
```bash
# Parse events
python3 parse_sysmon.py Sysmon.evtx

# Filter process creates
grep "EventID.*1" sysmon_parsed.json

# Filter network connections
grep "EventID.*3" sysmon_parsed.json
```

---

## Quality Assurance

### Verification Steps

1. Evidence integrity verified (hashes match)
2. Timeline correlation (all sources align)
3. Peer review conducted
4. Documentation complete
5. Findings reproducible

### Validation Criteria

- Evidence chain documented
- Analysis methodology sound
- Conclusions supported by evidence
- Alternative hypotheses considered
- Recommendations actionable

---

## Lessons Learned

### What Worked Well

Comprehensive logging (Sysmon)  
Quick memory acquisition  
Complete PCAP capture  
Multi-source correlation  

### Areas for Improvement

Earlier detection (EDR needed)  
Automated response (SOAR)  
Better user training  
Enhanced monitoring  

---

## References

- NIST Special Publication 800-86 (Guide to Integrating Forensic Techniques into Incident Response)
- SANS DFIR Methodology
- MITRE ATT&CK Framework
- Volatility 3 Documentation

---

**Investigator:** Jesse Antman  
**Date:** February 2026  
**Status:** Complete
