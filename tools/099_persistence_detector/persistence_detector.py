#!/usr/bin/env python3
"""Persistence Detector - Identifies persistence mechanisms (cron, init, launchd, registry)."""

import sys, os, json, argparse, re
from pathlib import Path

PERSISTENCE_LOCATIONS = {
    'crontab': '/var/spool/cron/crontabs/',
    'init.d': '/etc/init.d/',
    'systemd': '/etc/systemd/system/',
    'rc.local': '/etc/rc.local',
    'launchd': '/Library/LaunchAgents/'
}

SUSPICIOUS_PATTERNS = [
    r'(nc|ncat|netcat).*-l',
    r'(curl|wget).*\|.*bash',
    r'(powershell|cmd).*-enc',
    r'rm.*-rf',
    r'dd.*if=',
]

def scan_cron_jobs():
    """Scan for malicious cron jobs."""
    suspicious = []
    try:
        for user_cron in Path(PERSISTENCE_LOCATIONS['crontab']).glob('*'):
            with open(user_cron) as f:
                for i, line in enumerate(f, 1):
                    if line.strip() and not line.startswith('#'):
                        for pattern in SUSPICIOUS_PATTERNS:
                            if re.search(pattern, line):
                                suspicious.append({'file': str(user_cron), 'line': i, 'content': line.strip()})
    except:
        pass
    return suspicious

def scan_init_scripts():
    """Scan init.d scripts for persistence."""
    suspicious = []
    try:
        for script in Path(PERSISTENCE_LOCATIONS['init.d']).glob('*'):
            if script.is_file() and os.access(script, os.X_OK):
                with open(script, 'rb') as f:
                    content = f.read().decode('utf-8', errors='ignore')
                    for pattern in SUSPICIOUS_PATTERNS:
                        if re.search(pattern, content):
                            suspicious.append({'file': str(script), 'indicator': pattern})
    except:
        pass
    return suspicious

def main():
    p = argparse.ArgumentParser(description="Detect system persistence mechanisms")
    p.add_argument("--path", help="Custom path to scan")
    p.add_argument("--output", help="Output JSON file")
    args = p.parse_args()
    
    try:
        cron_sus = scan_cron_jobs()
        init_sus = scan_init_scripts()
        
        print(f"[+] Persistence Detection Report")
        print(f"    Suspicious cron jobs: {len(cron_sus)}")
        print(f"    Suspicious init.d scripts: {len(init_sus)}")
        
        if cron_sus:
            print(f"\n[!] MALICIOUS CRON JOBS:")
            for c in cron_sus[:3]:
                print(f"    {c['file']} line {c['line']}")
                print(f"       {c['content'][:60]}")
        
        if init_sus:
            print(f"\n[!] SUSPICIOUS INIT SCRIPTS:")
            for i in init_sus[:3]:
                print(f"    {i['file']}")
        
        if args.output:
            json.dump({'cron': cron_sus, 'init_d': init_sus}, open(args.output, 'w'), indent=2)
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
