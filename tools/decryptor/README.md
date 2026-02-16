# Ransomware Decryption Tool

## Overview

This tool decrypts files that were encrypted by the educational ransomware.

## Requirements
```bash
pip install cryptography
```

## Usage

### Basic Usage
```bash
python3 decrypt_files.py --key "9Wf1-APAw9C2sLDinvPOJGvWEop9a5C3d4nP8OAa7qw=" --directory "/path/to/files"
```

### Recursive Search
```bash
python3 decrypt_files.py --key "YOUR_KEY" --directory "/path/to/files" --recursive
```

## Finding the Key

The encryption key is stored in:
- `evidence/21a34484_key.txt`
- C2 server logs: `logs/c2_20260215.json`

## Example
```bash
# Windows
python decrypt_files.py --key "9Wf1-APAw9C2sLDinvPOJGvWEop9a5C3d4nP8OAa7qw=" --directory "C:\Users\Windows10\Documents" --recursive

# Linux
python3 decrypt_files.py --key "9Wf1-APAw9C2sLDinvPOJGvWEop9a5C3d4nP8OAa7qw=" --directory "./test_files" --recursive
```

## Output
```
======================================================================
Ransomware Decryption Tool
======================================================================

Key: 9Wf1-APAw9C2sLDinvPOJGvWEop9a5C3d4nP8OAa7qw=
Directory: ./test_files
Recursive: True

[*] Found 37 encrypted files

[+] Decrypted: Document_1.pdf.locked → Document_1.pdf
[+] Decrypted: Budget_Analysis.pdf.locked → Budget_Analysis.pdf
[+] Decrypted: Meeting_Notes.docx.locked → Meeting_Notes.docx
...

======================================================================
✅ Successfully decrypted: 37
❌ Failed to decrypt: 0
======================================================================
```

## Notes

- Original .locked files are deleted after successful decryption
- Invalid key will result in decryption failure
- Backup .locked files before attempting decryption

## For Educational Purposes Only

This tool is part of a forensic training exercise.
