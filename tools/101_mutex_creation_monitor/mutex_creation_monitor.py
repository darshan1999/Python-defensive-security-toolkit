#!/usr/bin/env python3
"""Mutex Creation Monitor - Detects mutex creation for malware identification."""

import sys, json, argparse
from datetime import datetime

def parse_mutex_log(text):
    """Parse mutex creation logs."""
    mutexes = []
    for line in text.strip().split('\n'):
        if 'mutex' in line.lower() or 'createmutexa' in line.lower():
            mutexes.append(line.strip())
    return mutexes

def detect_malware_mutexes(mutexes):
    """Detect known malware mutex patterns."""
    malware_patterns = {
        'WinFixer': ['WF_MUTEX', 'winfix_'],
        'Conficker': ['__CONFICKER__', 'c0nfck'],
        'Stuxnet': ['STUXNET_MTX', '_Stuxnet'],
        'ZeuS': ['ZEUS_MUTEX', '__zeus__'],
    }
    
    findings = []
    for mutex in mutexes:
        for malware, patterns in malware_patterns.items():
            for pattern in patterns:
                if pattern.lower() in mutex.lower():
                    findings.append({'mutex': mutex, 'malware': malware})
    
    return findings

def main():
    p = argparse.ArgumentParser(description="Monitor mutex creation for malware")
    p.add_argument("input", nargs='?', help="Log file with mutex data")
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    try:
        if args.input:
            with open(args.input) as f:
                text = f.read()
        else:
            text = sys.stdin.read()
        
        mutexes = parse_mutex_log(text)
        findings = detect_malware_mutexes(mutexes)
        
        print(f"[+] Mutex Monitor Report")
        print(f"    Total mutexes: {len(mutexes)}")
        print(f"    Malware indicators: {len(findings)}")
        
        if findings:
            print(f"\n[!] MALWARE MUTEXES DETECTED:")
            for f in findings[:5]:
                print(f"    {f['mutex'][:50]} -> {f['malware']}")
        
        if args.output:
            json.dump({'mutexes': mutexes[:50], 'findings': findings}, open(args.output, 'w'))
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
