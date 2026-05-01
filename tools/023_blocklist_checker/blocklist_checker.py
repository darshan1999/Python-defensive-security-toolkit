#!/usr/bin/env python3
"""Blocklist Checker - Queries IPs/domains against local and remote blocklists."""

import sys, os, json, argparse, urllib.request, urllib.error, re
from ipaddress import ip_address, AddressValueError

SAMPLE_BLOCKLIST = [
    "192.0.2.1", "192.0.2.2", "198.51.100.5", "203.0.113.10",
    "10.0.0.99", "172.16.0.50", "evil.com", "malware.net",
    "phishing-site.io", "c2-server.xyz"
]

def is_valid_ip_or_domain(target):
    """Validate if target is IP or domain."""
    try:
        ip_address(target)
        return 'ip'
    except AddressValueError:
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            return 'domain'
        return None

def load_local_blocklist(filepath):
    """Load local blocklist from file."""
    try:
        with open(filepath) as f:
            entries = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return entries
    except FileNotFoundError:
        return []

def check_local_blocklist(target, blocklist):
    """Check target against local blocklist."""
    if target in blocklist:
        return 'BLOCKED'
    for entry in blocklist:
        if entry.lower() in target.lower() or target.lower() in entry.lower():
            return 'BLOCKED'
    return None

def check_abuseipdb(ip, api_key):
    """Check IP against AbuseIPDB API."""
    try:
        url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90'
        req = urllib.request.Request(url, headers={'Key': api_key, 'Accept': 'application/json'})
        
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            confidence = data.get('data', {}).get('abuseConfidenceScore', 0)
            
            if confidence > 50:
                return 'MALICIOUS', confidence
            elif confidence > 0:
                return 'SUSPICIOUS', confidence
            else:
                return 'CLEAN', confidence
    except (urllib.error.URLError, urllib.error.HTTPError):
        return None, None
    except (ValueError, KeyError, json.JSONDecodeError):
        return None, None

def check_target(target, blocklist, api_key=None):
    """Check single target against all blocklists."""
    target_type = is_valid_ip_or_domain(target)
    if not target_type:
        return {'target': target, 'status': 'INVALID', 'reason': 'Invalid IP or domain'}
    
    local_result = check_local_blocklist(target, blocklist)
    if local_result:
        return {'target': target, 'status': 'BLOCKED', 'reason': 'Local blocklist', 'type': target_type}
    
    if api_key and target_type == 'ip':
        abuseipdb_status, confidence = check_abuseipdb(target, api_key)
        if abuseipdb_status:
            return {'target': target, 'status': abuseipdb_status, 'confidence': confidence, 'type': target_type}
    
    return {'target': target, 'status': 'CLEAN', 'type': target_type}

def create_sample_blocklist(filepath='blocklist.txt'):
    """Create sample blocklist for testing."""
    try:
        with open(filepath, 'w') as f:
            f.write("# Sample blocklist\n")
            for entry in SAMPLE_BLOCKLIST:
                f.write(f"{entry}\n")
        print(f"[+] Sample blocklist created: {filepath}")
        return 0
    except IOError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

def main():
    p = argparse.ArgumentParser(description="Check IPs/domains against blocklists")
    p.add_argument("targets", nargs='*', help="Targets to check")
    p.add_argument("--blocklist", help="Local blocklist file")
    p.add_argument("--api-key", help="AbuseIPDB API key")
    p.add_argument("--file", help="File with targets (one per line)")
    p.add_argument("--output", help="Output JSON file")
    p.add_argument("--create-sample", action='store_true', help="Create sample blocklist")
    args = p.parse_args()
    
    if args.create_sample:
        return create_sample_blocklist()
    
    if not args.targets and not args.file:
        p.print_help()
        return 1
    
    api_key = args.api_key or os.getenv('ABUSEIPDB_API_KEY')
    blocklist_file = args.blocklist or 'blocklist.txt'
    local_blocklist = load_local_blocklist(blocklist_file) if os.path.exists(blocklist_file) else []
    
    targets = list(args.targets)
    if args.file:
        try:
            with open(args.file) as f:
                targets.extend(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            return 1
    
    results = [check_target(t, local_blocklist, api_key) for t in targets]
    
    print(f"{'Target':<30} {'Status':<12} {'Info':<30}")
    print("=" * 72)
    for r in results:
        info = f"Confidence: {r.get('confidence', 'N/A')}" if 'confidence' in r else r.get('reason', '')
        print(f"{r['target']:<30} {r['status']:<12} {info:<30}")
    
    print(f"\n[+] Summary: Checked {len(results)} targets")
    print(f"    BLOCKED: {sum(1 for r in results if r['status'] == 'BLOCKED')}")
    print(f"    MALICIOUS: {sum(1 for r in results if r['status'] == 'MALICIOUS')}")
    
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"[+] Saved to {args.output}")
        except IOError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
    
    return 0 if all(r['status'] == 'CLEAN' for r in results) else 1

if __name__ == "__main__":
    sys.exit(main())
