#!/usr/bin/env python3
"""
Registry Key Extractor - Extracts sensitive Windows registry keys from Registry dumps or logs.
Identifies Run keys, Services, and persistence mechanisms (cross-platform friendly).
"""

import sys
import re
import argparse
import json
from collections import defaultdict

# Common persistence registry paths
PERSISTENCE_PATHS = [
    r'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    r'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    r'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    r'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services',
    r'HKEY_LOCAL_MACHINE\\Software\\Classes\\.exe\\shell\\open\\command',
]

SUSPICIOUS_VALUES = [
    'powershell', 'cmd.exe', 'cscript', 'wscript', 'certutil', 'bitsadmin',
    'rundll32', 'regsvr32', 'msiexec', 'tasklist', 'whoami'
]

def parse_registry_dump(text: str) -> dict:
    """Parse Windows registry dump format."""
    entries = defaultdict(list)
    current_path = None
    
    for line in text.split('\n'):
        line = line.strip()
        
        # Match registry paths
        if line.startswith('HKEY_'):
            current_path = line
        elif '=' in line and current_path:
            key_name, value = line.split('=', 1)
            entries[current_path].append({
                'name': key_name.strip().strip('"'),
                'value': value.strip().strip('"')
            })
    
    return entries

def extract_persistence_keys(registry: dict) -> list:
    """Extract persistence-related registry keys."""
    persistence_keys = []
    
    for path, entries in registry.items():
        for persistence_path in PERSISTENCE_PATHS:
            if persistence_path.lower() in path.lower():
                for entry in entries:
                    persistence_keys.append({
                        'path': path,
                        'name': entry['name'],
                        'value': entry['value'],
                        'type': 'persistence'
                    })
    
    return persistence_keys

def detect_suspicious_values(registry_entries: list) -> list:
    """Detect suspicious registry values."""
    suspicious = []
    
    for entry in registry_entries:
        value = entry.get('value', '').lower()
        for suspect in SUSPICIOUS_VALUES:
            if suspect in value:
                suspicious.append({
                    'path': entry['path'],
                    'name': entry['name'],
                    'value': entry['value'],
                    'reason': f'Contains {suspect}'
                })
                break
    
    return suspicious

def main():
    parser = argparse.ArgumentParser(
        description="Extract Windows registry keys from dump files",
        epilog="Example: python3 registry_key_extractor.py reg_dump.txt --output persistence.json"
    )
    parser.add_argument("input", nargs='?', default='-', help="Registry dump file or - for stdin")
    parser.add_argument("--output", help="Output JSON file")
    parser.add_argument("--filter", choices=['all', 'persistence', 'suspicious'], 
                       default='all', help="Filter extracted keys")
    
    args = parser.parse_args()
    
    try:
        if args.input == '-':
            text = sys.stdin.read()
        else:
            with open(args.input, 'rb') as f:
                text = f.read().decode('utf-8', errors='ignore')
        
        registry = parse_registry_dump(text)
        
        if not registry:
            print("[!] No registry keys found", file=sys.stderr)
            return 1
        
        print(f"[+] Registry Analysis Report")
        print(f"    Total registry paths: {len(registry)}")
        
        results = {'all': []}
        
        # Extract persistence keys
        persistence = extract_persistence_keys(registry)
        results['persistence'] = persistence
        results['all'].extend(persistence)
        print(f"    Persistence keys: {len(persistence)}")
        
        # Detect suspicious values
        all_entries = []
        for entries in registry.values():
            all_entries.extend(entries)
        
        suspicious = detect_suspicious_values(all_entries)
        results['suspicious'] = suspicious
        results['all'].extend([s for s in suspicious if s not in results['all']])
        print(f"    Suspicious entries: {len(suspicious)}")
        
        if args.filter in ['persistence', 'suspicious']:
            output_list = results[args.filter]
        else:
            output_list = results['all']
        
        if output_list:
            print(f"\n[!] FINDINGS ({len(output_list)} items):")
            for item in output_list[:10]:
                print(f"    {item['path']} \\ {item['name']}")
                print(f"      Value: {item['value']}")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n[+] Results saved to {args.output}")
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
