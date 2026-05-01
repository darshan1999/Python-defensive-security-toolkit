#!/usr/bin/env python3
"""
Ransomware Activity Monitor - Detects ransomware-like activity in directories.
Monitors for rapid file modifications, suspicious extensions, and ransom notes.
"""

import sys
import os
import json
import argparse
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

RANSOMWARE_EXTENSIONS = {'.encrypted', '.locked', '.crypto', '.crypt', '.zzz', 
                        '.cerber', '.locky', '.wannacry', '.notpetya', '.petya'}
RANSOM_NOTE_NAMES = {'readme.txt', 'readme.htm', 'decrypt.txt', 'help_decrypt.txt',
                     'how_to_restore.txt', 'restore_files.txt', 'payment.txt'}

def get_file_hash(filepath: str) -> str:
    """Calculate SHA256 hash of file."""
    try:
        return hashlib.sha256(open(filepath, 'rb').read()).hexdigest()
    except:
        return ""

def scan_directory(directory: str, baseline_file: str = None) -> dict:
    """Scan directory for ransomware indicators."""
    results = {
        'rapid_changes': [],
        'suspicious_extensions': [],
        'ransom_notes': [],
        'new_files': [],
        'score': 0
    }
    
    baseline = {}
    if baseline_file and os.path.exists(baseline_file):
        try:
            with open(baseline_file) as f:
                baseline = json.load(f)
        except:
            pass
    
    files_by_time = defaultdict(list)
    current_state = {}
    
    print(f"[*] Scanning {directory} for ransomware activity...")
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                mtime = os.path.getmtime(filepath)
                files_by_time[int(mtime)].append(filepath)
                file_hash = get_file_hash(filepath)
                current_state[filepath] = file_hash
                
                # Check for suspicious extensions
                if Path(file).suffix.lower() in RANSOMWARE_EXTENSIONS:
                    results['suspicious_extensions'].append(filepath)
                    results['score'] += 25
                    print(f"[!] Suspicious extension: {filepath}")
                
                # Check for ransom notes
                if file.lower() in RANSOM_NOTE_NAMES:
                    results['ransom_notes'].append(filepath)
                    results['score'] += 30
                    print(f"[!] Ransom note detected: {filepath}")
                
                # Check for new files
                if baseline and filepath not in baseline:
                    results['new_files'].append(filepath)
                    
            except Exception as e:
                pass
    
    # Check for rapid modifications
    recent_time = datetime.now() - timedelta(seconds=5)
    rapid_count = sum(len(files) for t, files in files_by_time.items() 
                     if datetime.fromtimestamp(t) > recent_time)
    
    if rapid_count > 10:
        results['rapid_changes'] = [f for t, files in files_by_time.items() 
                                   for f in files if datetime.fromtimestamp(t) > recent_time]
        results['score'] += 40
        print(f"[!] Rapid file modifications detected: {rapid_count} files in 5 seconds")
    
    # Save current baseline
    if baseline_file:
        with open(baseline_file, 'w') as f:
            json.dump(current_state, f)
    
    return results

def main():
    parser = argparse.ArgumentParser(description="Monitor directory for ransomware activity")
    parser.add_argument("directory", help="Directory to monitor")
    parser.add_argument("--baseline", default="ransomware_baseline.json", help="Baseline file")
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.directory):
        print(f"Error: {args.directory} is not a directory", file=sys.stderr)
        return 1
    
    try:
        results = scan_directory(args.directory, args.baseline)
        
        print(f"\n[*] Ransomware Activity Report")
        print(f"    Suspicious extensions: {len(results['suspicious_extensions'])}")
        print(f"    Ransom notes found: {len(results['ransom_notes'])}")
        print(f"    Rapid changes: {len(results['rapid_changes'])}")
        print(f"    New files: {len(results['new_files'])}")
        print(f"    Threat score: {results['score']}/100")
        
        if results['score'] > 50:
            print("\n[!] HIGH RISK: Possible ransomware activity detected!")
            return 1
        elif results['score'] > 20:
            print("\n[!] MEDIUM RISK: Suspicious activity detected")
            return 0
        else:
            print("\n[+] No ransomware indicators detected")
            return 0
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
