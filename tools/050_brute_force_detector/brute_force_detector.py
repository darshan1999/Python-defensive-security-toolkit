#!/usr/bin/env python3
"""Brute Force Detector - Detects brute force attack patterns in logs."""

import sys, re, json, argparse
from collections import defaultdict

def parse_auth_log(text):
    """Parse authentication log entries."""
    failed_logins = defaultdict(int)
    
    for line in text.strip().split('\n'):
        if re.search(r'failed|failure|invalid', line, re.IGNORECASE):
            # Try to extract username/IP
            user_match = re.search(r'user=(\S+)', line, re.IGNORECASE)
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            
            key = user_match.group(1) if user_match else (ip_match.group(1) if ip_match else 'unknown')
            failed_logins[key] += 1
    
    return failed_logins

def detect_brute_force(failed_logins, threshold=5):
    """Detect brute force attacks."""
    attacks = []
    for key, count in failed_logins.items():
        if count >= threshold:
            attacks.append({'target': key, 'attempts': count, 'threat': 'BRUTE_FORCE'})
    return attacks

def main():
    p = argparse.ArgumentParser(description="Detect brute force attacks")
    p.add_argument("input", nargs='?', default='-', help="Log file")
    p.add_argument("--threshold", type=int, default=5, help="Failure threshold")
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    try:
        if args.input == '-':
            text = sys.stdin.read()
        else:
            with open(args.input) as f:
                text = f.read()
        
        failed = parse_auth_log(text)
        attacks = detect_brute_force(failed, args.threshold)
        
        print(f"[+] Brute Force Detection Report")
        print(f"    Unique targets: {len(failed)}")
        print(f"    Brute force attacks: {len(attacks)}")
        
        if attacks:
            print(f"\n[!] BRUTE FORCE DETECTED:")
            for a in attacks:
                print(f"    {a['target']}: {a['attempts']} attempts")
        
        if args.output:
            json.dump(attacks, open(args.output, 'w'))
        
        return 0 if not attacks else 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
