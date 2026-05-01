#!/usr/bin/env python3
"""Network Monitor - Detects C2, exfiltration, and lateral movement."""

import sys, subprocess, argparse, json, re
from collections import defaultdict

C2_PORTS = [4444, 1337, 31337, 12345, 54321, 8888, 9999]

def parse_ss_output(text):
    """Parse ss -tan or netstat -tan output."""
    connections = []
    for line in text.strip().split('\n'):
        if not any(x in line for x in ['State', 'LISTEN']):
            continue
        parts = line.split()
        if len(parts) >= 4:
            try:
                local = parts[3] if 'ESTAB' in line else parts[2]
                remote = parts[4] if len(parts) > 4 and 'ESTAB' in line else None
                if remote:
                    connections.append({'local': local, 'remote': remote, 'state': 'ESTABLISHED'})
            except (IndexError, ValueError):
                pass
    return connections

def detect_c2_beaconing(conns):
    """Detect C2 beaconing patterns."""
    findings = []
    ip_counts = defaultdict(int)
    
    for c in conns:
        remote_ip = c['remote'].split(':')[0]
        ip_counts[remote_ip] += 1
    
    for ip, count in ip_counts.items():
        if count >= 3:
            findings.append({'ip': ip, 'issue': f'Beaconing: {count} connections to same IP'})
        
        # Check for C2 ports
        for c in conns:
            if c['remote'].startswith(ip):
                try:
                    port = int(c['remote'].split(':')[1])
                    if port in C2_PORTS:
                        findings.append({'ip': ip, 'port': port, 'issue': f'C2 port: {port}'})
                except (ValueError, IndexError):
                    pass
    
    return findings

def detect_lateral_movement(conns):
    """Detect lateral movement attempts."""
    lateral_ports = [445, 3389, 135, 22]
    findings = []
    
    for c in conns:
        try:
            remote_ip = c['remote'].split(':')[0]
            port = int(c['remote'].split(':')[1])
            
            if port in lateral_ports and remote_ip.startswith(('10.', '172.', '192.168.')):
                port_name = {445: 'SMB', 3389: 'RDP', 135: 'WMI', 22: 'SSH'}.get(port)
                findings.append({'target': remote_ip, 'port': port, 'protocol': port_name})
        except (ValueError, IndexError):
            pass
    
    return findings

def detect_exfiltration(conns):
    """Detect potential data exfiltration."""
    findings = []
    ip_counts = defaultdict(int)
    
    for c in conns:
        remote_ip = c['remote'].split(':')[0]
        ip_counts[remote_ip] += 1
    
    for ip, count in ip_counts.items():
        if count > 10:
            findings.append({'ip': ip, 'connections': count, 'issue': 'Connection flood'})
        
        for c in conns:
            if c['remote'].startswith(ip):
                try:
                    port = int(c['remote'].split(':')[1])
                    if port > 10000:
                        findings.append({'ip': ip, 'port': port, 'issue': f'High port: {port}'})
                except ValueError:
                    pass
    
    return findings

def main():
    p = argparse.ArgumentParser(description="Monitor network for C2 and exfiltration")
    p.add_argument("--input", help="netstat/ss output file")
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    try:
        if args.input:
            with open(args.input) as f:
                text = f.read()
        else:
            try:
                text = subprocess.check_output('ss -tan', shell=True, stderr=subprocess.DEVNULL).decode()
            except:
                text = subprocess.check_output('netstat -tan', shell=True, stderr=subprocess.DEVNULL).decode()
        
        conns = parse_ss_output(text)
        c2 = detect_c2_beaconing(conns)
        lateral = detect_lateral_movement(conns)
        exfil = detect_exfiltration(conns)
        
        print(f"[+] Network Monitor Report")
        print(f"    Total connections: {len(conns)}")
        print(f"    C2 indicators: {len(c2)}")
        print(f"    Lateral movement: {len(lateral)}")
        print(f"    Exfiltration alerts: {len(exfil)}")
        
        if c2:
            print(f"\n[!] C2 DETECTED:")
            for alert in c2[:5]:
                print(f"    {alert['ip']}: {alert['issue']}")
        
        if lateral:
            print(f"\n[!] LATERAL MOVEMENT:")
            for alert in lateral[:5]:
                print(f"    {alert['target']}:{alert['port']} ({alert['protocol']})")
        
        findings = c2 + lateral + exfil
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(findings[:50], f, indent=2)
        
        return 0 if not findings else 1
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
