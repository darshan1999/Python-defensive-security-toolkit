#!/usr/bin/env python3
"""Service Creation Detector - Identifies suspicious service installation."""

import sys, json, argparse, re
from collections import defaultdict

def parse_service_log(text):
    """Parse service creation events from logs."""
    services = []
    for line in text.strip().split('\n'):
        if 'service' in line.lower() and ('created' in line.lower() or 'start' in line.lower()):
            services.append(line.strip())
    return services

def detect_suspicious_services(services):
    """Detect suspicious service patterns."""
    suspicious_patterns = [
        r'rundll32', r'regsvr32', r'cmd\.exe', r'powershell',
        r'wscript', r'cscript', r'msiexec', r'certutil'
    ]
    
    findings = []
    for svc in services:
        for pattern in suspicious_patterns:
            if re.search(pattern, svc, re.IGNORECASE):
                findings.append({'service': svc, 'pattern': pattern})
                break
    
    return findings

def main():
    p = argparse.ArgumentParser(description="Detect suspicious service creation")
    p.add_argument("input", nargs='?', help="Log file")
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    try:
        if args.input:
            with open(args.input) as f:
                text = f.read()
        else:
            text = sys.stdin.read()
        
        services = parse_service_log(text)
        suspicious = detect_suspicious_services(services)
        
        print(f"[+] Service Creation Report")
        print(f"    Total services: {len(services)}")
        print(f"    Suspicious: {len(suspicious)}")
        
        if suspicious:
            print(f"\n[!] SUSPICIOUS SERVICES:")
            for s in suspicious[:5]:
                print(f"    {s['service'][:60]}")
        
        if args.output:
            json.dump({'services': services[:50], 'suspicious': suspicious}, open(args.output, 'w'))
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
