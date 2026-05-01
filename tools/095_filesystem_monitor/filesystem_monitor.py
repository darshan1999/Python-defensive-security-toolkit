#!/usr/bin/env python3
"""Filesystem Monitor - Detects rapid file modifications, suspicious extensions, and changes."""

import sys, os, json, argparse, stat
from datetime import datetime, timedelta
from collections import defaultdict

SUSPICIOUS_EXTENSIONS = ['.exe', '.com', '.scr', '.pif', '.vbs', '.js', '.ps1', '.bat', '.cmd']

def scan_directory(path, max_age_hours=24):
    """Scan directory for recently modified files."""
    recent = []
    threshold = datetime.now() - timedelta(hours=max_age_hours)
    
    try:
        for root, dirs, files in os.walk(path):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                    if mtime > threshold:
                        ext = os.path.splitext(file)[1].lower()
                        recent.append({
                            'path': filepath, 'modified': mtime.isoformat(),
                            'extension': ext, 'size': os.path.getsize(filepath)
                        })
                except:
                    pass
    except:
        pass
    
    return recent

def detect_mass_modifications(files):
    """Detect mass file modifications (ransomware indicator)."""
    ext_counts = defaultdict(int)
    for f in files:
        ext_counts[f['extension']] += 1
    
    anomalies = []
    for ext, count in ext_counts.items():
        if count > 10:
            anomalies.append({'indicator': 'MASS_MOD', 'extension': ext, 'count': count})
    
    return anomalies

def detect_suspicious_files(files):
    """Detect files with suspicious extensions in unexpected locations."""
    suspicious = []
    for f in files:
        ext = f['extension'].lower()
        if ext in SUSPICIOUS_EXTENSIONS and '/tmp/' not in f['path']:
            suspicious.append(f)
    return suspicious

def main():
    p = argparse.ArgumentParser(description="Monitor filesystem for suspicious modifications")
    p.add_argument("path", nargs='?', default='.', help="Directory to monitor")
    p.add_argument("--hours", type=int, default=24, help="Hours to look back")
    p.add_argument("--output", help="Output JSON file")
    args = p.parse_args()
    
    if not os.path.isdir(args.path):
        print(f"Error: {args.path} not found", file=sys.stderr)
        return 1
    
    files = scan_directory(args.path, args.hours)
    mass_mods = detect_mass_modifications(files)
    suspicious = detect_suspicious_files(files)
    
    print(f"[+] Filesystem Monitor Report")
    print(f"    Files modified (last {args.hours}h): {len(files)}")
    print(f"    Mass modification alerts: {len(mass_mods)}")
    print(f"    Suspicious files: {len(suspicious)}")
    
    if mass_mods:
        print(f"\n[!] MASS MODIFICATION DETECTED (ransomware indicator):")
        for m in mass_mods:
            print(f"    {m['extension']}: {m['count']} files")
    
    if suspicious:
        print(f"\n[!] SUSPICIOUS FILES:")
        for s in suspicious[:5]:
            print(f"    {s['path']} ({s['extension']})")
    
    if args.output:
        json.dump({'files': files[:50], 'mass_mods': mass_mods, 'suspicious': suspicious[:20]},
                 open(args.output, 'w'), indent=2)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
