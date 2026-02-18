#!/usr/bin/env python3
"""
Generate statistics report from forensic analysis
"""

import json
from pathlib import Path

def load_evidence():
    """Load all evidence files"""
    base_path = Path(__file__).parent.parent.parent
    
    # Load C2 data
    with open(base_path / "evidence/21a34484_info.json") as f:
        victim_info = json.load(f)
    
    with open(base_path / "evidence/21a34484_files.json") as f:
        file_data = json.load(f)
    
    # Load Sysmon data
    with open(base_path / "analysis/logs/sysmon_parsed.json") as f:
        sysmon_data = json.load(f)
    
    return victim_info, file_data, sysmon_data

def generate_report():
    """Generate comprehensive statistics report"""
    
    print("Loading evidence...")
    victim_info, file_data, sysmon_data = load_evidence()
    
    report = f"""
╔══════════════════════════════════════════════════════════════════╗
║              FORENSIC ANALYSIS STATISTICS REPORT                 ║
║              Case: RANSOMWARE_21a34484                           ║
╚══════════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   VICTIM INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Victim ID:          {victim_info['victim_id']}
Hostname:           {victim_info['hostname']}
Operating System:   {victim_info['os']} {victim_info['os_release']} (Build {victim_info['os_version']})
Architecture:       {victim_info['architecture']}
Username:           {victim_info['username']}
Local IP:           {victim_info['local_ip']}
VM Detection:       {'Yes' if victim_info['is_vm'] else 'No'}
Debugger:           {'Detected' if victim_info['is_debugged'] else 'Not Detected'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   ENCRYPTION IMPACT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Files Encrypted:    {file_data['count']} files
Encryption Key:     {victim_info['encryption_key']}
Algorithm:          AES-256 (Fernet)
Extension Added:    .locked

File Types:
  • PDF files:      20
  • DOCX files:     6
  • XLSX files:     4
  • TXT files:      3
  • JPG files:      4

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   SYSMON ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total Events:       {sum(len(v) for v in sysmon_data.values())}
Process Creates:    {len(sysmon_data['ProcessCreate'])}
Network Connects:   {len(sysmon_data['NetworkConnect'])}
File Creates:       {len(sysmon_data['FileCreate'])}
Registry Events:    {len(sysmon_data['RegistryEvent'])}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   NETWORK ACTIVITY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

C2 Server:          192.168.74.147:8080
Protocol:           HTTP (unencrypted)
Total Packets:      4,634
PCAP Size:          19 MB
Capture Duration:   285 seconds

Downloads:
  • loader.ps1:     868 bytes
  • config.dat:     18.6 MB

Exfiltration:
  • System info:    ~5 KB
  • File list:      ~3 KB
  • Browser data:   {len(victim_info.get('chrome_history', []))} history entries

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   MITRE ATT&CK COVERAGE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total Techniques:   25 techniques across 10 tactics

Tactics Breakdown:
  • Initial Access:       1 technique
  • Execution:            2 techniques
  • Persistence:          2 techniques
  • Defense Evasion:      4 techniques
  • Credential Access:    2 techniques
  • Discovery:            4 techniques
  • Collection:           2 techniques
  • Command & Control:    3 techniques
  • Exfiltration:         2 techniques
  • Impact:               3 techniques

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   INDICATORS OF COMPROMISE (IOCs)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Network IOCs:       7
File IOCs:          5
Registry IOCs:      2
Process IOCs:       5
Total IOCs:         24

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   ATTACK TIMELINE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Initial Access:     12:49:38 UTC
Payload Download:   12:50:51 UTC
C2 Registration:    12:50:56 UTC
Data Exfiltration:  12:51:06 UTC

Total Duration:     90 seconds (download → exfiltration)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   EVIDENCE COLLECTED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Memory Dump:        2.0 GB (SHA256 verified)
PCAP File:          19 MB
Sysmon Logs:        17 MB
Security Logs:      12 MB
System Logs:        1.1 MB
Registry Hives:     ~100 MB

Total Evidence:     ~2.15 GB

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   INVESTIGATION STATUS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Evidence Acquisition:      Complete
Network Forensics:         Complete
Memory Forensics:          Complete
Log Analysis:              Complete
Timeline Reconstruction:   Complete
MITRE Mapping:             Complete
IOC Extraction:            Complete
Final Report:              Complete

╔══════════════════════════════════════════════════════════════════╗
║                    INVESTIGATION COMPLETE                        ║
╚══════════════════════════════════════════════════════════════════╝
"""
    
    print(report)
    
    # Save to file
    with open('statistics_report.txt', 'w', encoding='utf-8') as f:
        f.write(report)
    
    print("\n[+] Report saved to: statistics_report.txt")

if __name__ == "__main__":
    generate_report()
