#!/usr/bin/env python3
"""Process Monitor - Detects suspicious processes and injection attempts."""

import sys, subprocess, argparse, json, re
from collections import defaultdict

def parse_ps_aux(text):
    """Parse ps aux output correctly."""
    processes = []
    for line in text.strip().split('\n')[1:]:
        parts = line.split(None, 10)
        if len(parts) >= 11:
            try:
                processes.append({
                    'user': parts[0],
                    'pid': int(parts[1]),
                    'cpu': float(parts[2]),
                    'mem': float(parts[3]),
                    'cmd': parts[10]
                })
            except (ValueError, IndexError):
                pass
    return processes

def detect_suspicious_locations(procs):
    """Flag processes from suspicious locations."""
    suspicious_paths = ['/tmp/', '/dev/shm/', '/var/tmp/']
    findings = []
    for p in procs:
        if any(path in p['cmd'] for path in suspicious_paths):
            findings.append({'pid': p['pid'], 'cmd': p['cmd'], 'issue': 'Suspicious location'})
    return findings

def detect_suspicious_names(procs):
    """Flag processes with suspicious names."""
    suspicious = ['nc', 'ncat', 'netcat', 'meterpreter', 'mimikatz', 'cobaltstrike']
    findings = []
    for p in procs:
        for term in suspicious:
            if term in p['cmd'].lower():
                findings.append({'pid': p['pid'], 'cmd': p['cmd'], 'issue': f'Suspicious: {term}'})
                break
    return findings

def detect_encoded_commands(procs):
    """Flag PowerShell/cmd with encoded arguments."""
    patterns = ['-enc', '-encodedcommand', '-e ']
    findings = []
    for p in procs:
        if any(re.search(pattern, p['cmd'], re.IGNORECASE) for pattern in patterns):
            findings.append({'pid': p['pid'], 'cmd': p['cmd'], 'issue': 'Encoded command'})
    return findings

def detect_unusual_parents(procs):
    """Flag unexpected parent-child relationships."""
    risky_parents = {'apache2': 'bash', 'nginx': 'bash', 'httpd': 'bash', 'tomcat': 'nc'}
    findings = []
    for p in procs:
        for parent, child in risky_parents.items():
            if parent in p['cmd'] and any(c in p['cmd'] for c in ['bash', 'sh', 'nc']):
                findings.append({'pid': p['pid'], 'cmd': p['cmd'], 'issue': f'{parent} spawning shell'})
    return findings

def detect_high_cpu(procs):
    """Flag processes with excessive CPU usage."""
    findings = []
    for p in procs:
        if p['cpu'] > 90.0:
            findings.append({'pid': p['pid'], 'cmd': p['cmd'], 'issue': f'High CPU: {p["cpu"]}%'})
    return findings

def main():
    p = argparse.ArgumentParser(description="Monitor processes for suspicious activity")
    p.add_argument("--input", help="ps aux output file")
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    try:
        if args.input:
            with open(args.input) as f:
                text = f.read()
        else:
            text = subprocess.check_output('ps aux', shell=True, stderr=subprocess.DEVNULL).decode()
        
        procs = parse_ps_aux(text)
        suspicious = []
        suspicious.extend(detect_suspicious_locations(procs))
        suspicious.extend(detect_suspicious_names(procs))
        suspicious.extend(detect_encoded_commands(procs))
        suspicious.extend(detect_unusual_parents(procs))
        suspicious.extend(detect_high_cpu(procs))
        
        print(f"[+] Process Monitor Report")
        print(f"    Total processes: {len(procs)}")
        print(f"    Suspicious: {len(suspicious)}")
        
        if suspicious:
            print(f"\n[!] SUSPICIOUS PROCESSES:")
            for s in suspicious[:10]:
                print(f"    PID {s['pid']}: {s['issue']}")
                print(f"       {s['cmd'][:70]}")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(suspicious[:50], f, indent=2)
        
        return 0 if not suspicious else 1
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(f"Error: File not found", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
