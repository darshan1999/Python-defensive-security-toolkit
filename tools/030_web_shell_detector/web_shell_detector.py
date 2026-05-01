#!/usr/bin/env python3
"""Web Shell Detector - Detects common web shell patterns in files."""

import sys, os, re, json, argparse
from pathlib import Path

WEB_SHELL_PATTERNS = [
    r'exec\s*\(\s*\$_',
    r'system\s*\(\s*\$_',
    r'passthru\s*\(',
    r'shell_exec\s*\(',
    r'\$_REQUEST\[',
    r'eval\s*\(',
    r'assert\s*\(',
]

def scan_file(filepath):
    """Scan file for web shell patterns."""
    findings = []
    try:
        with open(filepath, 'rb') as f:
            content = f.read().decode('utf-8', errors='ignore')
        
        for pattern in WEB_SHELL_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    'file': filepath,
                    'line': line_num,
                    'pattern': pattern,
                    'context': content[max(0, match.start()-30):match.end()+30]
                })
    except:
        pass
    
    return findings

def main():
    p = argparse.ArgumentParser(description="Detect web shells")
    p.add_argument("path", help="File or directory to scan")
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    try:
        all_findings = []
        
        if os.path.isfile(args.path):
            all_findings = scan_file(args.path)
        elif os.path.isdir(args.path):
            for file in Path(args.path).rglob('*.php'):
                all_findings.extend(scan_file(str(file)))
        
        print(f"[+] Web Shell Detection Report")
        print(f"    Target: {args.path}")
        print(f"    Findings: {len(all_findings)}")
        
        if all_findings:
            print(f"\n[!] POTENTIAL WEB SHELLS:")
            for f in all_findings[:5]:
                print(f"    {f['file']} line {f['line']}")
                print(f"       {f['pattern']}")
        
        if args.output:
            json.dump(all_findings[:50], open(args.output, 'w'), indent=2)
        
        return 0 if not all_findings else 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
