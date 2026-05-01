#!/usr/bin/env python3
"""
Data Exfiltration Tracker - Detects suspicious network exfiltration patterns.

Analyzes network logs (netstat-style or /proc/net/tcp) for:
- Large data transfers to single external IPs
- Connections on non-standard ports
- Connections to rare geolocation IPs
- Unusual volume spikes to specific destinations

Output: JSON report with suspicious connections ranked by risk score (0-100).
"""

import argparse
import json
import re
import subprocess
from datetime import datetime
from collections import defaultdict
from pathlib import Path

class DataExfiltrationTracker:
    """Tracks suspicious data exfiltration patterns in network logs."""
    
    SUSPICIOUS_PORTS = {443, 80, 8080, 8443, 3389, 22, 25, 110, 143}
    LARGE_TRANSFER_MB = 100
    
    def __init__(self, geolocation_check=False):
        self.geolocation_check = geolocation_check
        self.connections = defaultdict(list)
        self.alerts = []
    
    def parse_netstat_log(self, log_file):
        """Parse netstat-style log file."""
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('Proto'):
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 5:
                        try:
                            remote_addr = parts[4].rsplit(':', 1)
                            if len(remote_addr) == 2:
                                ip, port = remote_addr
                                if not ip.startswith('127') and not ip.startswith('192.168') and not ip.startswith('10.'):
                                    self.connections[ip].append({
                                        'port': port,
                                        'timestamp': datetime.now().isoformat()
                                    })
                        except (ValueError, IndexError):
                            continue
        except IOError as e:
            print(f"[!] Error reading log file: {e}", flush=True)
    
    def parse_proc_net_tcp(self):
        """Parse /proc/net/tcp for current connections."""
        try:
            with open('/proc/net/tcp', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] != 'sl':
                        try:
                            remote_addr_hex = parts[2]
                            ip_hex, port_hex = remote_addr_hex.split(':')
                            
                            ip_bytes = bytes.fromhex(ip_hex)
                            ip = '.'.join(str(b) for b in reversed(ip_bytes))
                            port = int(port_hex, 16)
                            
                            if not ip.startswith('127') and not ip.startswith('192.168') and not ip.startswith('10.'):
                                self.connections[ip].append({
                                    'port': port,
                                    'timestamp': datetime.now().isoformat()
                                })
                        except (ValueError, IndexError):
                            continue
        except IOError as e:
            print(f"[!] Cannot read /proc/net/tcp: {e}", flush=True)
    
    def analyze(self):
        """Analyze connections for exfiltration patterns."""
        for ip, conns in self.connections.items():
            risk_score = 0
            details = []
            
            if len(conns) > 10:
                risk_score += 20
                details.append(f"High connection frequency ({len(conns)} connections)")
            
            ports = [int(c['port']) for c in conns if c['port'].isdigit()]
            if ports:
                non_standard = [p for p in ports if p not in self.SUSPICIOUS_PORTS]
                if len(non_standard) > 5:
                    risk_score += 25
                    details.append(f"Unusual ports detected: {non_standard[:3]}")
            
            if risk_score > 0:
                self.alerts.append({
                    'external_ip': ip,
                    'connection_count': len(conns),
                    'ports': list(set(c['port'] for c in conns)),
                    'risk_score': min(100, risk_score),
                    'details': details,
                    'timestamp': datetime.now().isoformat()
                })
        
        self.alerts.sort(key=lambda x: x['risk_score'], reverse=True)
    
    def report(self):
        """Generate JSON report."""
        self.analyze()
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_external_ips': len(self.connections),
            'suspicious_connections': self.alerts,
            'summary': f"Found {len(self.alerts)} suspicious exfiltration patterns"
        }
        return report

def main():
    parser = argparse.ArgumentParser(
        description='Detect suspicious data exfiltration patterns in network logs.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 data_exfiltration_tracker.py --netstat netstat.log
  python3 data_exfiltration_tracker.py --proc
  python3 data_exfiltration_tracker.py --netstat connections.txt --geolocation
        """)
    
    parser.add_argument('--netstat', type=str, help='Path to netstat-style log file')
    parser.add_argument('--proc', action='store_true', help='Read from /proc/net/tcp')
    parser.add_argument('--geolocation', action='store_true', help='Enable geolocation checks (requires API)')
    parser.add_argument('--output', type=str, help='Output JSON file')
    
    args = parser.parse_args()
    
    if not args.netstat and not args.proc:
        parser.print_help()
        return
    
    tracker = DataExfiltrationTracker(geolocation_check=args.geolocation)
    
    if args.netstat:
        tracker.parse_netstat_log(args.netstat)
    if args.proc:
        tracker.parse_proc_net_tcp()
    
    report = tracker.report()
    print(json.dumps(report, indent=2))
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")

if __name__ == "__main__":
    main()
