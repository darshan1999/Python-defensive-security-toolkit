#!/usr/bin/env python3
"""ASEP Detector - Detects new persistence via auto-start extensions."""

import sys, os, json, argparse, re, pathlib

ASEP_PATHS = {
    'cron': ['/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.hourly/'],
    'init': ['/etc/init.d/', '/etc/systemd/system/'],
    'shell': [os.path.expanduser('~/.bashrc'), os.path.expanduser('~/.bash_profile'), os.path.expanduser('~/.profile')],
    'macos': [os.path.expanduser('~/Library/LaunchAgents/'), '/Library/LaunchAgents/', '/Library/LaunchDaemons/']
}

SUSPICIOUS_PATTERNS = [
    r'curl.*\|.*bash', r'wget.*\|.*bash', r'base64.*-d', r'/dev/tcp',
    r'nc -e', r'bash -i', r'meterpreter', r'powershell.*-enc'
]

def get_baseline_path():
    """Get baseline file path."""
    return os.path.expanduser('~/.asep_baseline.json')

def scan_asep_paths():
    """Scan all ASEP locations."""
    entries = {}
    
    for category, paths in ASEP_PATHS.items():
        for path in paths:
            if not os.path.exists(path):
                continue
            if os.path.isdir(path):
                for item in pathlib.Path(path).iterdir():
                    if item.is_file():
                        try:
                            entries[str(item)] = {'size': item.stat().st_size, 'category': category}
                        except:
                            pass
            elif os.path.isfile(path):
                try:
                    entries[path] = {'size': os.path.getsize(path), 'category': category}
                except:
                    pass
    
    return entries

def check_for_suspicious_content(filepath):
    """Check file for suspicious patterns."""
    try:
        with open(filepath, 'rb') as f:
            content = f.read().decode('utf-8', errors='ignore')
        
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False
    except:
        return False

def compare_baselines(baseline, current):
    """Compare baseline against current entries."""
    results = {'new': [], 'removed': [], 'unchanged': 0}
    
    # Find new entries
    for entry in current:
        if entry not in baseline:
            severity = 'CRITICAL' if check_for_suspicious_content(entry) else 'MEDIUM'
            if os.access(os.path.dirname(entry), os.W_OK):
                severity = 'HIGH'
            results['new'].append({'path': entry, 'severity': severity})
    
    # Find removed entries
    for entry in baseline:
        if entry not in current:
            results['removed'].append(entry)
    
    results['unchanged'] = sum(1 for e in baseline if e in current)
    return results

def main():
    p = argparse.ArgumentParser(description="Detect new auto-start extensions (ASEP)")
    p.add_argument("--baseline", action='store_true', help="Create baseline")
    p.add_argument("--reset", action='store_true', help="Delete baseline and reset")
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    baseline_path = get_baseline_path()
    
    if args.reset:
        if os.path.exists(baseline_path):
            os.remove(baseline_path)
            print("[+] Baseline reset")
        return 0
    
    current = scan_asep_paths()
    
    if args.baseline:
        with open(baseline_path, 'w') as f:
            json.dump(list(current.keys()), f)
        print(f"[+] Baseline created: {len(current)} entries")
        return 0
    
    # Check mode
    if not os.path.exists(baseline_path):
        print("[!] No baseline found. Run with --baseline first")
        return 1
    
    try:
        with open(baseline_path) as f:
            baseline = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    results = compare_baselines(baseline, list(current.keys()))
    
    print(f"[+] ASEP Detection Report")
    print(f"    Baseline entries: {len(baseline)}")
    print(f"    Current entries: {len(current)}")
    print(f"    New entries: {len(results['new'])}")
    print(f"    Removed: {len(results['removed'])}")
    print(f"    Unchanged: {results['unchanged']}")
    
    if results['new']:
        print(f"\n[!] NEW ENTRIES DETECTED:")
        for entry in results['new']:
            print(f"    [{entry['severity']}] {entry['path']}")
    
    if results['removed']:
        print(f"\n[*] Removed entries: {len(results['removed'])}")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[+] Saved to {args.output}")
    
    return 1 if results['new'] else 0

if __name__ == "__main__":
    sys.exit(main())
