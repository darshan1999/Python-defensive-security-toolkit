#!/usr/bin/env python3
"""
Hash Extractor - Extracts file hashes from text files and threat intelligence reports.
Identifies MD5, SHA1, SHA256, SHA512 hashes with validation.
"""

import sys
import re
import json
import argparse
from pathlib import Path
from collections import defaultdict

def extract_hashes(text: str) -> dict:
    """Extract hashes from text."""
    hashes = {
        'md5': set(),
        'sha1': set(),
        'sha256': set(),
        'sha512': set()
    }
    
    # Patterns for each hash type
    patterns = {
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b',
        'sha512': r'\b[a-fA-F0-9]{128}\b'
    }
    
    for hash_type, pattern in patterns.items():
        for match in re.finditer(pattern, text):
            hash_val = match.group(0).lower()
            hashes[hash_type].add(hash_val)
    
    return hashes

def validate_hashes(hashes: dict) -> dict:
    """Validate and deduplicate hashes."""
    validated = {
        'md5': [],
        'sha1': [],
        'sha256': [],
        'sha512': []
    }
    
    # SHA256 might contain SHA1, SHA512 might contain SHA256, etc.
    # Deduplicate by length
    all_hashes = []
    
    for h in hashes['md5']:
        all_hashes.append((h, 'md5'))
    for h in hashes['sha1']:
        all_hashes.append((h, 'sha1'))
    for h in hashes['sha256']:
        all_hashes.append((h, 'sha256'))
    for h in hashes['sha512']:
        all_hashes.append((h, 'sha512'))
    
    # Sort by hash value to group duplicates
    seen = set()
    for h, h_type in sorted(all_hashes, key=lambda x: x[0]):
        if h not in seen:
            validated[h_type].append(h)
            seen.add(h)
    
    return validated

def main():
    parser = argparse.ArgumentParser(
        description="Extract file hashes from text files or reports",
        epilog="Examples:\n  python3 hash_extractor.py report.txt\n  python3 hash_extractor.py malware_report.pdf --output hashes.json"
    )
    parser.add_argument("input", nargs='?', default='-', help="Input file or - for stdin")
    parser.add_argument("--output", help="Output JSON file")
    parser.add_argument("--type", choices=['md5', 'sha1', 'sha256', 'sha512', 'all'], 
                       default='all', help="Hash type to extract")
    
    args = parser.parse_args()
    
    try:
        # Read input
        if args.input == '-':
            text = sys.stdin.read()
        else:
            if not Path(args.input).exists():
                print(f"Error: {args.input} not found", file=sys.stderr)
                return 1
            with open(args.input, 'rb') as f:
                # Try to read as text, fallback to binary
                try:
                    text = f.read().decode('utf-8', errors='ignore')
                except:
                    text = f.read().decode('latin-1', errors='ignore')
        
        # Extract hashes
        hashes = extract_hashes(text)
        validated = validate_hashes(hashes)
        
        # Filter by type if specified
        if args.type != 'all':
            filtered = {args.type: validated[args.type]}
            validated = filtered
        
        # Output
        print(f"[+] Hash Extraction Report")
        total_hashes = sum(len(v) for v in validated.values())
        print(f"    Total hashes found: {total_hashes}")
        
        for hash_type, hash_list in validated.items():
            if hash_list:
                print(f"\n[{hash_type.upper()}] - {len(hash_list)} found")
                for h in sorted(hash_list)[:10]:
                    print(f"    {h}")
                if len(hash_list) > 10:
                    print(f"    ... and {len(hash_list) - 10} more")
        
        # Save JSON if requested
        if args.output:
            output_data = {
                'total_hashes': total_hashes,
                'hashes_by_type': {k: v for k, v in validated.items() if v}
            }
            with open(args.output, 'w') as f:
                json.dump(output_data, f, indent=2)
            print(f"\n[+] Results saved to {args.output}")
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
