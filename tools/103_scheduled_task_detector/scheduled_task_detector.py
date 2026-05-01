#!/usr/bin/env python3
"""Scheduled Task Detector - Identifies suspicious scheduled task creation."""

import sys, json, argparse, re

def parse_task_log(text):
    """Parse scheduled task events."""
    tasks = []
    for line in text.strip().split('\n'):
        if 'task' in line.lower() and 'schedul' in line.lower():
            tasks.append(line.strip())
    return tasks

def detect_suspicious_tasks(tasks):
    """Detect suspicious task patterns."""
    suspicious = []
    patterns = [r'powershell', r'cmd', r'vbs', r'ps1', r'bat', r'rundll32', r'regsvr32']
    
    for task in tasks:
        for pattern in patterns:
            if re.search(pattern, task, re.IGNORECASE):
                suspicious.append(task)
                break
    
    return suspicious

def main():
    p = argparse.ArgumentParser(description="Detect suspicious scheduled tasks")
    p.add_argument("input", nargs='?', help="Log file")
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    try:
        if args.input:
            with open(args.input) as f:
                text = f.read()
        else:
            text = sys.stdin.read()
        
        tasks = parse_task_log(text)
        suspicious = detect_suspicious_tasks(tasks)
        
        print(f"[+] Task Detector Report")
        print(f"    Total tasks: {len(tasks)}")
        print(f"    Suspicious: {len(suspicious)}")
        
        if suspicious:
            print(f"\n[!] SUSPICIOUS TASKS:")
            for t in suspicious[:5]:
                print(f"    {t[:70]}")
        
        if args.output:
            json.dump({'tasks': len(tasks), 'suspicious': len(suspicious)}, open(args.output, 'w'))
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
