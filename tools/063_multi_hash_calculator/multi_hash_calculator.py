#!/usr/bin/env python3
"""Multi Hash Calculator - Calculates multiple hash formats for files."""

import sys, hashlib, argparse, json, os

def calculate_hashes(filepath):
    """Calculate MD5, SHA1, SHA256 hashes."""
    hashes = {}
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        hashes['md5'] = hashlib.md5(data).hexdigest()
        hashes['sha1'] = hashlib.sha1(data).hexdigest()
        hashes['sha256'] = hashlib.sha256(data).hexdigest()
    except:
        pass
    
    return hashes

def main():
    p = argparse.ArgumentParser(description="Calculate multi-format hashes")
    p.add_argument("file", help="File to hash")
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    if not os.path.isfile(args.file):
        print(f"Error: {args.file} not found", file=sys.stderr)
        return 1
    
    try:
        hashes = calculate_hashes(args.file)
        
        print(f"[+] Hash Report: {os.path.basename(args.file)}")
        for hash_type, value in hashes.items():
            print(f"    {hash_type.upper()}: {value}")
        
        if args.output:
            json.dump({'file': args.file, **hashes}, open(args.output, 'w'))
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
