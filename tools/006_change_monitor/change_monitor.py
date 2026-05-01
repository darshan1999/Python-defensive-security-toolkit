#!/usr/bin/env python3
"""Change Monitor - Monitors configuration changes on systems."""

import sys, os, hashlib, json, argparse
from pathlib import Path

def calculate_file_hash(filepath):
    """Calculate MD5 hash of file."""
    try:
        with open(filepath, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except:
        return None

def scan_config_dir(path, extensions=['.conf', '.cfg', '.config']):
    """Scan directory for config files."""
    configs = {}
    try:
        for file in Path(path).rglob('*'):
            if any(file.name.endswith(ext) for ext in extensions):
                hash_val = calculate_file_hash(str(file))
                if hash_val:
                    configs[str(file)] = hash_val
    except:
        pass
    return configs

def compare_hashes(old, new):
    """Compare old and new hashes."""
    changes = []
    for file in new:
        if file not in old:
            changes.append({'file': file, 'change': 'NEW'})
        elif old[file] != new[file]:
            changes.append({'file': file, 'change': 'MODIFIED'})
    
    for file in old:
        if file not in new:
            changes.append({'file': file, 'change': 'DELETED'})
    
    return changes

def main():
    p = argparse.ArgumentParser(description="Monitor configuration changes")
    p.add_argument("--path", default="/etc", help="Path to monitor")
    p.add_argument("--baseline", help="Baseline hash file")
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    try:
        current = scan_config_dir(args.path)
        changes = []
        
        if args.baseline:
            with open(args.baseline) as f:
                baseline = json.load(f)
            changes = compare_hashes(baseline, current)
        
        print(f"[+] Change Monitor Report")
        print(f"    Path: {args.path}")
        print(f"    Files: {len(current)}")
        print(f"    Changes: {len(changes)}")
        
        for c in changes[:5]:
            print(f"    {c['change']}: {c['file'][:50]}")
        
        if args.output:
            json.dump({'files': list(current.items())[:50], 'changes': changes}, 
                     open(args.output, 'w'), indent=2)
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
