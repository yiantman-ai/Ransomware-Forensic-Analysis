#!/usr/bin/env python3
"""
Ransomware Decryption Tool
===========================

Decrypts files encrypted by the educational ransomware.

Usage:
    python3 decrypt_files.py --key <encryption_key> --directory <path>

Example:
    python3 decrypt_files.py --key "9Wf1-APAw9C2sLDinvPOJGvWEop9a5C3d4nP8OAa7qw=" --directory "C:\Users\Windows10\Documents"

Author: Jesse Antman
Case: RANSOMWARE_21a34484
"""

import os
import sys
import argparse
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken

def decrypt_file(encrypted_path, key):
    """Decrypt a single .locked file"""
    try:
        fernet = Fernet(key.encode() if isinstance(key, str) else key)
        
        # Read encrypted file
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt
        decrypted_data = fernet.decrypt(encrypted_data)
        
        # Write decrypted file (remove .locked extension)
        original_path = str(encrypted_path).replace('.locked', '')
        with open(original_path, 'wb') as f:
            f.write(decrypted_data)
        
        print(f"[+] Decrypted: {Path(encrypted_path).name} → {Path(original_path).name}")
        
        # Remove .locked file
        os.remove(encrypted_path)
        
        return True
        
    except InvalidToken:
        print(f"[-] Invalid key for: {Path(encrypted_path).name}")
        return False
    except Exception as e:
        print(f"[-] Error decrypting {Path(encrypted_path).name}: {e}")
        return False

def find_locked_files(directory):
    """Find all .locked files in directory"""
    locked_files = []
    
    for file in Path(directory).rglob("*.locked"):
        locked_files.append(file)
    
    return locked_files

def main():
    parser = argparse.ArgumentParser(description='Decrypt ransomware-encrypted files')
    parser.add_argument('--key', required=True, help='Encryption key from C2 server')
    parser.add_argument('--directory', required=True, help='Directory containing .locked files')
    parser.add_argument('--recursive', action='store_true', help='Search subdirectories')
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("Ransomware Decryption Tool")
    print("=" * 70)
    print(f"\nKey: {args.key}")
    print(f"Directory: {args.directory}")
    print(f"Recursive: {args.recursive}\n")
    
    # Find locked files
    if args.recursive:
        locked_files = find_locked_files(args.directory)
    else:
        locked_files = list(Path(args.directory).glob("*.locked"))
    
    if not locked_files:
        print("[!] No .locked files found")
        return
    
    print(f"[*] Found {len(locked_files)} encrypted files\n")
    
    # Decrypt files
    success_count = 0
    fail_count = 0
    
    for file in locked_files:
        if decrypt_file(file, args.key):
            success_count += 1
        else:
            fail_count += 1
    
    print("\n" + "=" * 70)
    print(f"✅ Successfully decrypted: {success_count}")
    print(f"❌ Failed to decrypt: {fail_count}")
    print("=" * 70)

if __name__ == "__main__":
    main()
