#!/usr/bin/env python3
"""
Persistence Detection Tool - Detects common persistence mechanisms on Linux/macOS.
Checks crontab, cron directories, init scripts, shell rc files, and launchd services.
"""

import sys
import os
import subprocess
import argparse
import re
from pathlib import Path

SUSPICIOUS_PATTERNS = [
    (r'\d+\.\d+\.\d+\.\d+', 'IP address'),
    (r'https?://', 'URL'),
    (r'base64', 'Base64 encoding'),
    (r'eval\(', 'eval() function'),
    (r'exec\(', 'exec() function'),
    (r'bash -i', 'Interactive bash'),
    (r'nc ', 'Netcat'),
    (r'whoami', 'Privilege check'),
]

def check_crontab() -> list:
    """Check user and system crontab entries."""
    findings = []
    
    try:
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if line.strip() and not line.startswith('#'):
                    for pattern, desc in SUSPICIOUS_PATTERNS:
                        if re.search(pattern, line, re.IGNORECASE):
                            findings.append(('crontab', line, desc))
    except:
        pass
    
    # Check system cron directories
    cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.weekly', '/etc/cron.monthly']
    for cron_dir in cron_dirs:
        if os.path.isdir(cron_dir):
            for file in os.listdir(cron_dir):
                filepath = os.path.join(cron_dir, file)
                try:
                    with open(filepath) as f:
                        content = f.read()
                        for pattern, desc in SUSPICIOUS_PATTERNS:
                            if re.search(pattern, content, re.IGNORECASE):
                                findings.append((cron_dir, filepath, desc))
                except:
                    pass
    
    return findings

def check_init_scripts() -> list:
    """Check /etc/init.d for suspicious scripts."""
    findings = []
    init_dir = '/etc/init.d'
    
    if not os.path.isdir(init_dir):
        return findings
    
    for file in os.listdir(init_dir):
        filepath = os.path.join(init_dir, file)
        try:
            with open(filepath) as f:
                content = f.read()
                for pattern, desc in SUSPICIOUS_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        findings.append(('init.d', filepath, desc))
        except:
            pass
    
    return findings

def check_shell_files() -> list:
    """Check ~/.bashrc, ~/.bash_profile, ~/.profile, /etc/profile.d."""
    findings = []
    home = os.path.expanduser('~')
    shell_files = [
        os.path.join(home, '.bashrc'),
        os.path.join(home, '.bash_profile'),
        os.path.join(home, '.profile'),
        os.path.join(home, '.zshrc'),
        '/etc/profile',
        '/etc/profile.d'
    ]
    
    for path in shell_files:
        if not path.endswith('/'):
            if os.path.isfile(path):
                try:
                    with open(path) as f:
                        content = f.read()
                        for pattern, desc in SUSPICIOUS_PATTERNS:
                            if re.search(pattern, content, re.IGNORECASE):
                                findings.append(('shell', path, desc))
                except:
                    pass
        elif os.path.isdir(path):
            for file in os.listdir(path):
                filepath = os.path.join(path, file)
                try:
                    with open(filepath) as f:
                        content = f.read()
                        for pattern, desc in SUSPICIOUS_PATTERNS:
                            if re.search(pattern, content, re.IGNORECASE):
                                findings.append(('profile.d', filepath, desc))
                except:
                    pass
    
    return findings

def check_launchd() -> list:
    """Check LaunchAgents and LaunchDaemons on macOS."""
    findings = []
    launch_dirs = [
        os.path.expanduser('~/Library/LaunchAgents'),
        '/Library/LaunchAgents',
        '/Library/LaunchDaemons'
    ]
    
    for launch_dir in launch_dirs:
        if os.path.isdir(launch_dir):
            for file in os.listdir(launch_dir):
                filepath = os.path.join(launch_dir, file)
                try:
                    with open(filepath) as f:
                        content = f.read()
                        for pattern, desc in SUSPICIOUS_PATTERNS:
                            if re.search(pattern, content, re.IGNORECASE):
                                findings.append(('launchd', filepath, desc))
                except:
                    pass
    
    return findings

def main():
    parser = argparse.ArgumentParser(
        description="Detect persistence mechanisms on Linux/macOS"
    )
    parser.add_argument("--check-all", action="store_true", help="Check all persistence locations")
    
    args = parser.parse_args()
    
    print("[*] Scanning for persistence mechanisms...")
    
    all_findings = []
    all_findings.extend(check_crontab())
    all_findings.extend(check_init_scripts())
    all_findings.extend(check_shell_files())
    all_findings.extend(check_launchd())
    
    print(f"\n[*] Persistence Detection Report")
    print(f"    Total suspicious entries: {len(all_findings)}")
    
    if all_findings:
        print(f"\n[!] Suspicious entries detected:")
        for location, file, indicator in all_findings:
            print(f"    [{location}] {file}")
            print(f"        Indicator: {indicator}")
        return 1
    else:
        print("[+] No persistence mechanisms detected")
        return 0

if __name__ == "__main__":
    sys.exit(main())
