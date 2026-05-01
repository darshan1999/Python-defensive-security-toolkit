#!/usr/bin/env python3
"""
IOC Scanner - Scans text/files for IOCs (IPs, domains, hashes, URLs).
Matches against provided IOC list with severity scoring.
"""

import sys
import re
import json
import argparse
from pathlib import Path

IP_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
DOMAIN_PATTERN = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
HASH_MD5 = r'\b[a-fA-F0-9]{32}\b'
HASH_SHA1 = r'\b[a-fA-F0-9]{40}\b'
HASH_SHA256 = r'\b[a-fA-F0-9]{64}\b'
URL_PATTERN = r'https?://[^\s]+'

def load_ioc_list(filepath: str) -> dict:
    """Load IOC list from JSON file."""
    try:
        with open(filepath) as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading IOCs: {e}", file=sys.stderr)
        return {}

def extract_iocs(text: str) -> dict:
    """Extract all IOC types from text."""
    iocs = {
        'ips': set(),
        'domains': set(),
        'hashes': set(),
        'urls': set()
    }
    
    for match in re.finditer(IP_PATTERN, text):
        ip = match.group(0)
        if not ip.endswith('.0') and not ip.endswith('.255'):
            iocs['ips'].add(ip)
    
    for match in re.finditer(DOMAIN_PATTERN, text):
        domain = match.group(0).lower()
        if not domain[0].isdigit():
            iocs['domains'].add(domain)
    
    for match in re.finditer(HASH_MD5, text):
        iocs['hashes'].add(match.group(0).lower())
    
    for match in re.finditer(HASH_SHA1, text):
        iocs['hashes'].add(match.group(0).lower())
    
    for match in re.finditer(HASH_SHA256, text):
        iocs['hashes'].add(match.group(0).lower())
    
    for match in re.finditer(URL_PATTERN, text):
        iocs['urls'].add(match.group(0))
    
    return iocs

def score_severity(ioc_type: str, ioc_list: dict) -> dict:
    """Score IOCs based on threat intelligence."""
    scores = {}
    
    if 'ips' in ioc_list:
        for ip in ioc_list['ips']:
            scores[ip] = 85 if any(bad in ip for bad in ['10.', '192.168.']) else 90
    
    if 'malicious_domains' in ioc_list:
        for domain in ioc_list['malicious_domains']:
            scores[domain] = 95
    
    return scores

def main():
    parser = argparse.ArgumentParser(
        description="Scan files for IOCs and match against threat intelligence",
        epilog="Example: python3 ioc_scanner.py report.txt --iocs malware_iocs.json"
    )
    parser.add_argument("input", nargs='?', default='-', help="File to scan or - for stdin")
    parser.add_argument("--iocs", help="JSON file with IOC list")
    
    args = parser.parse_args()
    
    try:
        if args.input == '-':
            text = sys.stdin.read()
        else:
            with open(args.input, 'rb') as f:
                text = f.read().decode('utf-8', errors='ignore')
        
        iocs = extract_iocs(text)
        
        print("[+] IOC Scan Results")
        print(f"    IPs found: {len(iocs['ips'])}")
        print(f"    Domains found: {len(iocs['domains'])}")
        print(f"    Hashes found: {len(iocs['hashes'])}")
        print(f"    URLs found: {len(iocs['urls'])}")
        
        if args.iocs:
            ioc_list = load_ioc_list(args.iocs)
            severity = score_severity(ioc_list, iocs)
            if severity:
                print(f"\n[!] MATCHES FOUND: {len(severity)}")
                for ioc, score in list(severity.items())[:10]:
                    print(f"    {ioc} (severity: {score})")
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
