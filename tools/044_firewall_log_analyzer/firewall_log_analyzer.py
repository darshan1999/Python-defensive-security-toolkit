#!/usr/bin/env python3
"""Firewall Log Analyzer - Analyzes firewall logs for security events."""

import sys, re, json, argparse
from collections import Counter

BLOCKED_PATTERN = r'BLOCK|DENY|REJECT'
ALLOWED_PATTERN = r'ALLOW|ACCEPT|PERMIT'

def parse_firewall_log(text):
    """Parse firewall log entries."""
    entries = []
    for line in text.strip().split('\n'):
        if re.search(BLOCKED_PATTERN, line, re.IGNORECASE):
            entries.append({'action': 'BLOCKED', 'line': line})
        elif re.search(ALLOWED_PATTERN, line, re.IGNORECASE):
            entries.append({'action': 'ALLOWED', 'line': line})
    return entries

def analyze_patterns(entries):
    """Analyze log patterns."""
    actions = Counter(e['action'] for e in entries)
    
    return {
        'total': len(entries),
        'blocked': actions.get('BLOCKED', 0),
        'allowed': actions.get('ALLOWED', 0),
        'block_rate': actions.get('BLOCKED', 0) / max(len(entries), 1)
    }

def main():
    p = argparse.ArgumentParser(description="Analyze firewall logs")
    p.add_argument("input", nargs='?', default='-', help="Log file or stdin")
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    try:
        if args.input == '-':
            text = sys.stdin.read()
        else:
            with open(args.input) as f:
                text = f.read()
        
        entries = parse_firewall_log(text)
        analysis = analyze_patterns(entries)
        
        print(f"[+] Firewall Log Analysis")
        print(f"    Total events: {analysis['total']}")
        print(f"    Blocked: {analysis['blocked']}")
        print(f"    Allowed: {analysis['allowed']}")
        print(f"    Block rate: {analysis['block_rate']:.1%}")
        
        if args.output:
            json.dump(analysis, open(args.output, 'w'))
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
