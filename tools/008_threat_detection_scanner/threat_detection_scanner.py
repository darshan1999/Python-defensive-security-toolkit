#!/usr/bin/env python3
"""
Threat Detection Scanner - Scans target IP for high-risk open ports.
Identifies ports like Telnet (23), FTP (21), SMB (445), RDP (3389), VNC (5900),
MSSQL (1433), MongoDB (27017) and reports risk levels.
"""

import sys
import socket
import argparse
from typing import List, Tuple

HIGH_RISK_PORTS = {
    23: ("Telnet", "CRITICAL"),
    21: ("FTP", "CRITICAL"),
    445: ("SMB", "CRITICAL"),
    3389: ("RDP", "HIGH"),
    5900: ("VNC", "HIGH"),
    1433: ("MSSQL", "HIGH"),
    27017: ("MongoDB", "HIGH")
}

def scan_port(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a port is open using socket connection."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except (socket.gaierror, socket.error, OSError):
        return False

def scan_target(target: str, port_list: List[int] = None) -> List[Tuple[int, str, str]]:
    """Scan target IP for high-risk open ports."""
    if port_list is None:
        port_list = list(HIGH_RISK_PORTS.keys())
    
    results = []
    print(f"[*] Scanning {target} for high-risk ports...")
    
    for port in sorted(port_list):
        if scan_port(target, port):
            service, risk = HIGH_RISK_PORTS.get(port, ("Unknown", "MEDIUM"))
            results.append((port, service, risk))
            print(f"[+] {port:5d}/tcp {service:15s} {risk:8s} - OPEN")
        else:
            print(f"[-] {port:5d}/tcp - CLOSED")
    
    return results

def main():
    parser = argparse.ArgumentParser(
        description="Scan target for high-risk open ports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python3 threat_detection_scanner.py 192.168.1.100\n  python3 threat_detection_scanner.py scanme.nmap.org --ports 22,80,443"
    )
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--ports", help="Comma-separated list of ports (default: high-risk only)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Connection timeout in seconds (default: 2.0)")
    
    args = parser.parse_args()
    
    port_list = None
    if args.ports:
        try:
            port_list = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            print("Error: Invalid port specification", file=sys.stderr)
            sys.exit(1)
    
    try:
        results = scan_target(args.target, port_list)
        
        print(f"\n[*] Scan Summary for {args.target}")
        print(f"    Total open ports: {len(results)}")
        
        critical = sum(1 for _, _, risk in results if risk == "CRITICAL")
        high = sum(1 for _, _, risk in results if risk == "HIGH")
        if critical > 0:
            print(f"    CRITICAL: {critical}")
        if high > 0:
            print(f"    HIGH: {high}")
            
        return 0 if len(results) == 0 else 1
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        return 2
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
