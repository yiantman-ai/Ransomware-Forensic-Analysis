# Quick Start Guide

Fast track to understanding this forensic investigation.

## 📋 TL;DR

**What happened:** Educational ransomware encrypted 37 files in 90 seconds via social engineering.

**How we know:** Complete forensic analysis with memory dump, PCAP, and event logs.

**Outcome:** Attack chain reconstructed, 25 MITRE techniques identified, 24 IOCs extracted.

---

## 🚀 5-Minute Overview

### 1. Read the Executive Summary
```bash
cat reports/05_Final_Report.md | head -100
```

### 2. View the Attack Timeline
```bash
cat analysis/timeline/attack_flow.txt
```

### 3. Check Key Evidence
```bash
# Encryption key (CRITICAL)
cat evidence/21a34484_key.txt

# Victim info
cat evidence/21a34484_info.json

# Encrypted files
cat evidence/21a34484_files.json
```

### 4. See Network Activity
```bash
# View in Wireshark
wireshark pcap/attack_full.pcap

# Or quick text view
tshark -r pcap/attack_full.pcap -Y "http" | head -20
```

### 5. Review IOCs
```bash
cat analysis/iocs/iocs_full.csv
```

---

## 📚 30-Minute Deep Dive

### Phase 1: Understand the Attack (10 min)

1. **Read attack summary:**
```bash
   cat attack_summary.txt
```

2. **View timeline:**
```bash
   cat analysis/timeline/super_timeline.csv
```

3. **Read network analysis:**
```bash
   cat reports/01_Network_Forensics.md
```

### Phase 2: Examine Evidence (10 min)

1. **Memory analysis:**
```bash
   cat reports/02_Memory_Forensics.md
```

2. **Sysmon results:**
```bash
   cat analysis/logs/sysmon_summary.txt
```

3. **Process execution:**
```bash
   cat analysis/memory/pslist_full.txt | grep -E "winupdate|powershell"
```

### Phase 3: Review Findings (10 min)

1. **MITRE ATT&CK:**
```bash
   cat docs/MITRE_ATTACK.md
```

2. **IOCs:**
```bash
   cat analysis/iocs/iocs.json | jq .
```

3. **Recommendations:**
```bash
   cat reports/05_Final_Report.md | grep -A 50 "Recommendations"
```

---

## 🎓 Full Investigation (2+ hours)

### Day 1: Network Forensics

1. Open Wireshark with PCAP
2. Follow TCP streams
3. Extract HTTP objects
4. Build network timeline

**Guide:** `reports/01_Network_Forensics.md`

### Day 2: Memory Forensics

1. Install Volatility 3
2. Run process analysis
3. Check network connections
4. Extract command lines

**Guide:** `reports/02_Memory_Forensics.md`

### Day 3: Log Analysis

1. Parse Sysmon events
2. Correlate with memory
3. Build process tree
4. Identify persistence

**Guide:** `analysis/logs/sysmon_summary.txt`

### Day 4: Synthesis

1. Create super timeline
2. Map to MITRE ATT&CK
3. Extract all IOCs
4. Write final report

**Guide:** `reports/05_Final_Report.md`

---

## 🛠️ Using the Tools

### Decryption Tool
```bash
cd tools/decryptor
python3 decrypt_files.py --key "9Wf1-APAw9C2sLDinvPOJGvWEop9a5C3d4nP8OAa7qw=" --directory /path/to/files --recursive
```

### IOC Scanner
```bash
cd tools/ioc_scanner
python3 scan_iocs.py
```

### Visualization
```bash
cd tools/visualization
python3 create_timeline_graph.py
```

### Statistics
```bash
cd tools/visualization
python3 generate_stats.py
```

---

## 📊 Key Files

| File | Description |
|------|-------------|
| `README.md` | Project overview |
| `reports/05_Final_Report.md` | Complete analysis (50+ pages) |
| `analysis/timeline/attack_flow.txt` | Visual attack flow |
| `evidence/21a34484_key.txt` | Encryption key (CRITICAL) |
| `analysis/iocs/iocs_full.csv` | All IOCs |
| `docs/MITRE_ATTACK.md` | 25 techniques mapped |
| `malware/source_code/advanced_ransomware.py` | Malware code |

---

## 🎯 Learning Paths

### For Students

1. Start with attack timeline
2. Read network analysis
3. Try memory forensics
4. Practice with tools

### For Professionals

1. Review methodology
2. Examine evidence chain
3. Validate findings
4. Adapt techniques

### For Researchers

1. Study MITRE mapping
2. Analyze malware code
3. Review detection rules
4. Contribute improvements

---

## ❓ FAQ

**Q: Can I run the malware?**  
A: Only in isolated lab environments. Educational purposes only.

**Q: How do I decrypt files?**  
A: Use `tools/decryptor/decrypt_files.py` with the key from `evidence/21a34484_key.txt`

**Q: Where are the large files?**  
A: Memory dump and PCAP are excluded from Git (.gitignore). Contact for access.

**Q: Can I use this for training?**  
A: Yes! That's exactly what it's designed for.

---

## 📞 Support

- **Issues:** GitHub Issues
- **Questions:** GitHub Discussions
- **Security:** Contact maintainer privately

---

**Happy Investigating! 🔍**
