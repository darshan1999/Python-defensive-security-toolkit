#!/usr/bin/env python3
"""Registry Monitor - Monitors Windows registry for suspicious modifications (cross-platform)."""

import sys, json, argparse
from datetime import datetime

def parse_registry_file(filepath):
    """Parse registry dump file."""
    entries = []
    with open(filepath, 'rb') as f:
        text = f.read().decode('utf-8', errors='ignore')
    
    for line in text.split('\n'):
        line = line.strip()
        if '=' in line and not line.startswith('['):
            entries.append(line)
    
    return entries

def detect_persistence_keys(entries):
    """Detect persistence-related registry modifications."""
    persistence_patterns = ['CurrentVersion\\Run', 'Services', 'shell\\open\\command', 'AppInit_DLLs']
    persistence = []
    
    for entry in entries:
        for pattern in persistence_patterns:
            if pattern.lower() in entry.lower():
                persistence.append(entry)
    
    return persistence

def detect_suspicious_values(entries):
    """Detect suspicious registry values."""
    suspicious_terms = ['powershell', 'cmd', 'rundll32', 'regsvr32', 'certutil', 'bitsadmin']
    suspicious = []
    
    for entry in entries:
        for term in suspicious_terms:
            if term in entry.lower():
                suspicious.append(entry)
    
    return suspicious

def main():
    p = argparse.ArgumentParser(description="Monitor registry for suspicious modifications")
    p.add_argument("input", nargs='?', help="Registry dump file")
    p.add_argument("--output", help="Output JSON file")
    args = p.parse_args()
    
    try:
        if not args.input:
            print("[!] Registry monitoring on Linux/Mac: simulated mode", file=sys.stderr)
            entries = []
        else:
            entries = parse_registry_file(args.input)
        
        persistence = detect_persistence_keys(entries)
        suspicious = detect_suspicious_values(entries)
        
        print(f"[+] Registry Monitor Report")
        print(f"    Registry entries analyzed: {len(entries)}")
        print(f"    Persistence indicators: {len(persistence)}")
        print(f"    Suspicious values: {len(suspicious)}")
        
        if persistence:
            print(f"\n[!] PERSISTENCE DETECTED:")
            for p in persistence[:5]:
                print(f"    {p[:80]}")
        
        if suspicious:
            print(f"\n[!] SUSPICIOUS REGISTRY:")
            for s in suspicious[:5]:
                print(f"    {s[:80]}")
        
        if args.output:
            json.dump({'persistence': persistence[:20], 'suspicious': suspicious[:20]},
                     open(args.output, 'w'), indent=2)
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
