#!/usr/bin/env python3
"""IP Address Extractor - Extracts IP addresses from text and files."""

import sys, re, argparse, json
from collections import Counter

IP_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

def extract_ips(text):
    """Extract IP addresses."""
    ips = set()
    for match in re.finditer(IP_PATTERN, text):
        ip = match.group(0)
        if not (ip.endswith('.0') or ip.endswith('.255')):
            ips.add(ip)
    return list(ips)

def categorize_ips(ips):
    """Categorize IPs."""
    private_ranges = ['10.', '172.16.', '172.31.', '192.168.', '127.']
    
    private = [ip for ip in ips if any(ip.startswith(p) for p in private_ranges)]
    public = [ip for ip in ips if ip not in private]
    
    return {'private': private, 'public': public}

def main():
    p = argparse.ArgumentParser(description="Extract IP addresses")
    p.add_argument("input", nargs='?', default='-', help="File or stdin")
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    try:
        if args.input == '-':
            text = sys.stdin.read()
        else:
            with open(args.input, 'rb') as f:
                text = f.read().decode('utf-8', errors='ignore')
        
        ips = extract_ips(text)
        categories = categorize_ips(ips)
        
        print(f"[+] IP Extraction Report")
        print(f"    Total IPs: {len(ips)}")
        print(f"    Public: {len(categories['public'])}")
        print(f"    Private: {len(categories['private'])}")
        
        if args.output:
            json.dump(categories, open(args.output, 'w'))
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
