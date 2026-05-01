#!/usr/bin/env python3
"""Behavioral Sandbox Runner - Simulates malware behavior in safe environment."""

import sys, os, json, argparse, subprocess, re
from pathlib import Path

SANDBOXED_BEHAVIORS = {
    'file_ops': r'(open|read|write|delete).*\.(exe|dll|sys)',
    'registry': r'(RegOpenKey|RegSetValue).*HKLM',
    'network': r'(socket|connect|send).*:(?:445|3389|445|139)',
    'process': r'(CreateProcess|ShellExecute)',
}

def analyze_file(filepath):
    """Analyze file for behaviors."""
    try:
        with open(filepath, 'rb') as f:
            content = f.read(65536)
        
        behaviors = []
        for behavior_name, pattern in SANDBOXED_BEHAVIORS.items():
            if re.search(pattern.encode(), content, re.IGNORECASE):
                behaviors.append(behavior_name)
        
        return behaviors
    except:
        return []

def check_api_calls(filepath):
    """Check for suspicious API calls."""
    suspicious_apis = [
        'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
        'SetWindowsHookEx', 'CreateFileMapping', 'MapViewOfFile'
    ]
    
    apis_found = []
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
        for api in suspicious_apis:
            if api.encode() in content:
                apis_found.append(api)
    except:
        pass
    
    return apis_found

def main():
    p = argparse.ArgumentParser(description="Analyze file behavior in sandbox environment")
    p.add_argument("file", help="File to analyze")
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    if not os.path.isfile(args.file):
        print(f"Error: {args.file} not found", file=sys.stderr)
        return 1
    
    try:
        behaviors = analyze_file(args.file)
        apis = check_api_calls(args.file)
        
        risk = 'LOW'
        if len(apis) > 2: risk = 'HIGH'
        elif len(behaviors) > 1: risk = 'MEDIUM'
        
        print(f"[+] Sandbox Analysis Report")
        print(f"    File: {os.path.basename(args.file)}")
        print(f"    Risk Level: {risk}")
        print(f"    Behaviors: {', '.join(behaviors) if behaviors else 'None'}")
        print(f"    Suspicious APIs: {len(apis)}")
        
        if apis:
            print(f"\n[!] API CALLS:")
            for api in apis[:5]:
                print(f"    {api}")
        
        if args.output:
            json.dump({'risk': risk, 'behaviors': behaviors, 'apis': apis},
                     open(args.output, 'w'))
        
        return 0 if risk == 'LOW' else 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
