# Detection Rules for Ransomware

This directory contains detection rules in multiple formats for identifying the ransomware attack.

## Contents

1. **Snort/Suricata Rules** (`snort_rules.rules`)
   - Network-based detection
   - C2 communication patterns
   - Payload download detection

2. **Sigma Rules** (`sigma_rules.yml`)
   - SIEM-agnostic detection
   - Process creation
   - Registry changes
   - File modifications

3. **YARA Rules** (`yara_rules.yar`)
   - Malware binary detection
   - Network traffic patterns
   - PowerShell loader detection

## Usage

### Snort/Suricata
```bash
# Add to Snort configuration
include /path/to/snort_rules.rules

# Test rules
snort -T -c /etc/snort/snort.conf

# Run Snort with rules
snort -A console -q -c /etc/snort/snort.conf -i eth0
```

### Sigma
```bash
# Convert to Splunk
sigmac -t splunk sigma_rules.yml

# Convert to Elastic
sigmac -t es-qs sigma_rules.yml

# Convert to QRadar
sigmac -t qradar sigma_rules.yml
```

### YARA
```bash
# Scan file
yara yara_rules.yar /path/to/suspicious.exe

# Scan directory
yara -r yara_rules.yar /path/to/directory/

# Scan with metadata
yara -m yara_rules.yar /path/to/file
```

## Rule Coverage

| Rule Type | Count | Coverage |
|-----------|-------|----------|
| Snort | 7 | Network C2, Payload downloads |
| Sigma | 5 | Process, Registry, File events |
| YARA | 3 | Binary, Traffic, Loader |

## Integration

These rules can be integrated into:
- **SIEM:** Splunk, ELK, QRadar, Sentinel
- **IDS/IPS:** Snort, Suricata, Zeek
- **EDR:** CrowdStrike, SentinelOne, Carbon Black
- **Threat Hunting:** TheHive, MISP

## Testing

Test data is available in the main repository:
- PCAP: `pcap/attack_full.pcap`
- Memory dump: Contact for access
- Malware binary: Educational purposes only
