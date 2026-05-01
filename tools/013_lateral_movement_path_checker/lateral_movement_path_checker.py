#!/usr/bin/env python3
"""
Lateral Movement Path Checker - Checks lateral movement paths between two IPs.
Tests SMB (445), RDP (3389), WMI (135), SSH (22) with MITRE ATT&CK references.
"""

import argparse
import socket

class LateralMovementPathChecker:
    """Checks lateral movement attack paths between two hosts."""
    
    def __init__(self, timeout=3):
        self.timeout = timeout
        self.paths = {
            22: {'service': 'SSH', 'technique': 'T1021.004', 'name': 'SSH'},
            135: {'service': 'WMI', 'technique': 'T1021.006', 'name': 'Windows Management Instrumentation'},
            445: {'service': 'SMB', 'technique': 'T1021.002', 'name': 'SMB/Windows Admin Shares'},
            3389: {'service': 'RDP', 'technique': 'T1021.001', 'name': 'Remote Desktop Protocol'},
        }
        self.results = {}
    
    def check_port(self, host, port):
        """Check if port is open on target."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception as e:
            return False
    
    def check_paths(self, source_ip, target_ip):
        """Check lateral movement paths between source and target."""
        print(f"\n[*] Checking lateral movement paths: {source_ip} -> {target_ip}")
        print("-" * 80)
        print(f"{'Port':<6} {'Service':<10} {'Status':<8} {'MITRE ATT&CK':<15} {'Technique Name':<30}")
        print("-" * 80)
        
        open_paths = []
        
        for port, info in self.paths.items():
            is_open = self.check_port(target_ip, port)
            status = "OPEN" if is_open else "CLOSED"
            status_symbol = "✓" if is_open else "✗"
            
            print(f"{port:<6} {info['service']:<10} {status_symbol} {status:<7} {info['technique']:<15} {info['name']:<30}")
            
            if is_open:
                open_paths.append({
                    'port': port,
                    'service': info['service'],
                    'technique': info['technique'],
                    'name': info['name']
                })
            
            self.results[port] = {
                'service': info['service'],
                'status': is_open,
                'technique': info['technique'],
                'technique_name': info['name']
            }
        
        print("-" * 80)
        
        if open_paths:
            print(f"\n[!] LATERAL MOVEMENT PATHS AVAILABLE: {len(open_paths)} techniques")
            print("\n[ATTACK SCENARIOS]")
            for path in open_paths:
                print(f"  - {path['technique']}: {path['name']} on port {path['port']}")
            print(f"\n[!] Risk Level: {'CRITICAL' if len(open_paths) >= 2 else 'HIGH' if len(open_paths) == 1 else 'LOW'}")
        else:
            print(f"\n[+] No lateral movement paths detected")
        
        return open_paths
    
    def validate_ips(self, source_ip, target_ip):
        """Validate IP addresses."""
        import re
        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        
        if not re.match(ip_pattern, source_ip) or not re.match(ip_pattern, target_ip):
            print("[-] Invalid IP address format")
            return False
        return True

def main():
    parser = argparse.ArgumentParser(
        description='Check lateral movement attack paths between two hosts.'
    )
    parser.add_argument('source_ip', help='Source IP address')
    parser.add_argument('target_ip', help='Target IP address')
    parser.add_argument('-t', '--timeout', type=int, default=3, help='Socket timeout in seconds (default: 3)')
    
    args = parser.parse_args()
    
    checker = LateralMovementPathChecker(timeout=args.timeout)
    
    if checker.validate_ips(args.source_ip, args.target_ip):
        checker.check_paths(args.source_ip, args.target_ip)
    else:
        exit(1)

if __name__ == "__main__":
    main()
