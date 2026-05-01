#!/usr/bin/env python3
"""
Baseline Comparison Tool - Compares two directory baselines to detect changes.
Identifies files added, removed, modified, or unchanged between snapshots.
"""

import sys
import json
import argparse
from pathlib import Path

def load_baseline(baseline_file: str) -> dict:
    """Load baseline JSON file."""
    try:
        with open(baseline_file) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading baseline: {e}", file=sys.stderr)
        return None

def compare_baselines(baseline1_file: str, baseline2_file: str) -> dict:
    """Compare two baselines."""
    baseline1 = load_baseline(baseline1_file)
    baseline2 = load_baseline(baseline2_file)
    
    if not baseline1 or not baseline2:
        return None
    
    files1 = baseline1.get('files', {})
    files2 = baseline2.get('files', {})
    
    comparison = {
        'only_in_baseline1': [],
        'only_in_baseline2': [],
        'modified': [],
        'unchanged': [],
        'summary': {}
    }
    
    print(f"[*] Comparing baselines...")
    print(f"    Baseline 1: {len(files1)} files")
    print(f"    Baseline 2: {len(files2)} files")
    
    # Files only in baseline1 (deleted)
    for filepath in files1:
        if filepath not in files2:
            comparison['only_in_baseline1'].append(filepath)
    
    # Files only in baseline2 (added)
    for filepath in files2:
        if filepath not in files1:
            comparison['only_in_baseline2'].append(filepath)
    
    # Files in both - check for modifications
    for filepath in files1:
        if filepath in files2:
            hash1 = files1[filepath].get('sha256')
            hash2 = files2[filepath].get('sha256')
            
            if hash1 == hash2:
                comparison['unchanged'].append(filepath)
            else:
                comparison['modified'].append({
                    'filepath': filepath,
                    'hash_before': hash1,
                    'hash_after': hash2,
                    'size_before': files1[filepath].get('size'),
                    'size_after': files2[filepath].get('size')
                })
    
    # Summary
    comparison['summary'] = {
        'deleted': len(comparison['only_in_baseline1']),
        'added': len(comparison['only_in_baseline2']),
        'modified': len(comparison['modified']),
        'unchanged': len(comparison['unchanged'])
    }
    
    return comparison

def print_report(comparison: dict):
    """Print comparison report."""
    print("\n[*] Baseline Comparison Report")
    summary = comparison['summary']
    print(f"    Added files: {summary['added']}")
    print(f"    Deleted files: {summary['deleted']}")
    print(f"    Modified files: {summary['modified']}")
    print(f"    Unchanged files: {summary['unchanged']}")
    
    if comparison['modified']:
        print(f"\n[!] Modified Files ({len(comparison['modified'])}):")
        for item in comparison['modified']:
            print(f"    {item['filepath']}")
            print(f"      Size: {item['size_before']} -> {item['size_after']} bytes")
            print(f"      Hash: {item['hash_before'][:16]}... -> {item['hash_after'][:16]}...")
    
    if comparison['only_in_baseline2']:
        print(f"\n[+] Added Files ({len(comparison['only_in_baseline2'])}):")
        for filepath in comparison['only_in_baseline2'][:10]:
            print(f"    {filepath}")
        if len(comparison['only_in_baseline2']) > 10:
            print(f"    ... and {len(comparison['only_in_baseline2']) - 10} more")
    
    if comparison['only_in_baseline1']:
        print(f"\n[-] Deleted Files ({len(comparison['only_in_baseline1'])}):")
        for filepath in comparison['only_in_baseline1'][:10]:
            print(f"    {filepath}")
        if len(comparison['only_in_baseline1']) > 10:
            print(f"    ... and {len(comparison['only_in_baseline1']) - 10} more")

def main():
    parser = argparse.ArgumentParser(
        description="Compare two directory baselines",
        epilog="Example: python3 baseline_comparison_tool.py baseline1.json baseline2.json"
    )
    parser.add_argument("baseline1", help="First baseline file")
    parser.add_argument("baseline2", help="Second baseline file")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    
    if not (Path(args.baseline1).exists() and Path(args.baseline2).exists()):
        print("Error: Baseline files not found", file=sys.stderr)
        return 1
    
    try:
        comparison = compare_baselines(args.baseline1, args.baseline2)
        
        if comparison is None:
            return 1
        
        if args.json:
            print(json.dumps(comparison, indent=2))
        else:
            print_report(comparison)
        
        # Return warning if changes detected
        if comparison['summary']['modified'] > 0 or comparison['summary']['added'] > 0:
            return 1
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
