# Web Infrastructure - Phishing & C2 Server

**⚠️ WARNING: FOR EDUCATIONAL PURPOSES ONLY**

This directory contains the complete web infrastructure used in the ransomware attack simulation.

## 📁 Contents

### 1. Phishing Website

**Files:**
- `index.html` - Fake Facebook login page
- `style.css` - Styling (mimics Facebook)
- `script.js` - Popup functionality with malicious PowerShell command

### 2. C2 Server

**File:** `c2_server.py`

**Endpoints:**
- `GET /` - Phishing page
- `GET /loader.ps1` - PowerShell loader (868 bytes)
- `GET /config.dat` - Base64-encoded malware (18.6 MB)
- `POST /register` - Victim registration + encryption key
- `POST /exfiltrate` - Encrypted file list

## 🚀 Usage (Educational Lab Only)
```bash
pip install flask
python3 c2_server.py
```

Server starts on: `http://0.0.0.0:8080`

## ⚠️ Legal Notice

FOR AUTHORIZED SECURITY RESEARCH AND EDUCATION ONLY.

**Permitted:**
✅ Educational labs (isolated networks)
✅ Security training
✅ Red team exercises (with authorization)

**Prohibited:**
❌ Deploying against real users
❌ Any malicious activity

**Maintainer:** Jesse Antman  
**Repository:** https://github.com/yiantman-ai/Ransomware-Forensic-Analysis
