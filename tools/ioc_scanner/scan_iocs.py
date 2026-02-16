#!/usr/bin/env python3
"""
IOC Scanner for Ransomware Artifacts
=====================================

Scans a system for indicators of compromise from the ransomware attack.

Author: Jesse Antman
Case: RANSOMWARE_21a34484
"""

import os
import sys
import json
import winreg
import subprocess
from pathlib import Path
from datetime import datetime

# Load IOCs
IOCS = {
    "file_paths": [
        r"C:\Users\*\AppData\Local\Temp\winupdate*.exe",
        r"C:\Users\*\Desktop\README_DECRYPT.txt"
    ],
    "file_extensions": [".locked"],
    "registry_keys": [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsSecurityUpdate"
    ],
    "scheduled_tasks": ["MicrosoftEdgeUpdate"],
    "network_ips": ["192.168.74.147"],
    "network_ports": [8080],
    "process_names": ["winupdate*.exe", "powershell.exe"],
    "command_patterns": [
        "IEX",
        "DownloadString",
        "loader.ps1",
        "config.dat"
    ]
}

def check_files():
    """Check for suspicious files"""
    print("\n[*] Checking for suspicious files...")
    findings = []
    
    for pattern in IOCS["file_paths"]:
        try:
            for file in Path("C:\\").rglob(pattern.split("\\")[-1]):
                findings.append({
                    "type": "file",
                    "ioc": str(file),
                    "severity": "HIGH"
                })
                print(f"    [!] Found: {file}")
        except:
            pass
    
    # Check for .locked files
    for ext in IOCS["file_extensions"]:
        try:
            for file in Path(Path.home()).rglob(f"*{ext}"):
                findings.append({
                    "type": "file",
                    "ioc": str(file),
                    "severity": "CRITICAL"
                })
                print(f"    [!] Encrypted file: {file}")
        except:
            pass
    
    return findings

def check_registry():
    """Check for persistence in registry"""
    print("\n[*] Checking registry...")
    findings = []
    
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_READ
        )
        
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
                if "WindowsSecurityUpdate" in name:
                    findings.append({
                        "type": "registry",
                        "ioc": f"{name} = {value}",
                        "severity": "CRITICAL"
                    })
                    print(f"    [!] Malicious Run key: {name} = {value}")
                i += 1
            except WindowsError:
                break
                
        winreg.CloseKey(key)
    except Exception as e:
        print(f"    [-] Registry check failed: {e}")
    
    return findings

def check_scheduled_tasks():
    """Check for malicious scheduled tasks"""
    print("\n[*] Checking scheduled tasks...")
    findings = []
    
    try:
        result = subprocess.run(
            'schtasks /query /fo CSV /v',
            shell=True,
            capture_output=True,
            text=True
        )
        
        for task_name in IOCS["scheduled_tasks"]:
            if task_name in result.stdout:
                findings.append({
                    "type": "scheduled_task",
                    "ioc": task_name,
                    "severity": "HIGH"
                })
                print(f"    [!] Malicious task: {task_name}")
                
    except Exception as e:
        print(f"    [-] Task check failed: {e}")
    
    return findings

def check_processes():
    """Check for malicious processes"""
    print("\n[*] Checking running processes...")
    findings = []
    
    try:
        result = subprocess.run(
            'tasklist',
            shell=True,
            capture_output=True,
            text=True
        )
        
        for proc_pattern in IOCS["process_names"]:
            pattern = proc_pattern.replace("*", "")
            if pattern in result.stdout:
                findings.append({
                    "type": "process",
                    "ioc": pattern,
                    "severity": "CRITICAL"
                })
                print(f"    [!] Malicious process: {pattern}")
                
    except Exception as e:
        print(f"    [-] Process check failed: {e}")
    
    return findings

def generate_report(all_findings):
    """Generate JSON report"""
    report = {
        "scan_time": datetime.now().isoformat(),
        "total_findings": len(all_findings),
        "findings": all_findings,
        "summary": {
            "CRITICAL": len([f for f in all_findings if f.get("severity") == "CRITICAL"]),
            "HIGH": len([f for f in all_findings if f.get("severity") == "HIGH"]),
            "MEDIUM": len([f for f in all_findings if f.get("severity") == "MEDIUM"])
        }
    }
    
    report_file = f"ioc_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n[+] Report saved: {report_file}")
    return report

def main():
    print("=" * 70)
    print("IOC Scanner - Ransomware Detection")
    print("Case: RANSOMWARE_21a34484")
    print("=" * 70)
    
    all_findings = []
    
    # Run all checks
    all_findings.extend(check_files())
    all_findings.extend(check_registry())
    all_findings.extend(check_scheduled_tasks())
    all_findings.extend(check_processes())
    
    # Generate report
    report = generate_report(all_findings)
    
    # Summary
    print("\n" + "=" * 70)
    print("SCAN SUMMARY")
    print("=" * 70)
    print(f"Total IOCs found: {report['total_findings']}")
    print(f"  CRITICAL: {report['summary']['CRITICAL']}")
    print(f"  HIGH: {report['summary']['HIGH']}")
    print(f"  MEDIUM: {report['summary']['MEDIUM']}")
    
    if report['total_findings'] > 0:
        print("\n[!] SYSTEM IS COMPROMISED - Immediate action required!")
    else:
        print("\n[+] No IOCs detected - System appears clean")
    
    print("=" * 70)

if __name__ == "__main__":
    main()
