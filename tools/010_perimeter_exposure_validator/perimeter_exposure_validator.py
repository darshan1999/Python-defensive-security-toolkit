#!/usr/bin/env python3
"""
Perimeter Exposure Validator - Validates which ports on a target are exposed externally.
Compares expected open ports against actual scan results and reports compliance.
"""

import sys
import socket
import argparse

def scan_port(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def validate_perimeter(host: str, expected_ports: list) -> dict:
    """Validate perimeter exposure."""
    risky_ports = [21, 23, 445, 3389, 5900, 1433, 27017]
    all_test_ports = set(expected_ports + risky_ports + [22, 80, 443])
    
    actual_open = []
    results = {'compliant': [], 'risk': [], 'unexpected': []}
    
    print(f"[*] Scanning {host} for exposure...")
    
    for port in sorted(all_test_ports):
        is_open = scan_port(host, port)
        
        if is_open:
            actual_open.append(port)
            
            if port in expected_ports:
                results['compliant'].append(port)
                print(f"[+] Port {port:5d} OPEN (expected)")
            elif port in risky_ports:
                results['risk'].append((port, "Risky port open"))
                print(f"[-] Port {port:5d} OPEN (HIGH RISK)")
            else:
                results['unexpected'].append(port)
                print(f"[!] Port {port:5d} OPEN (unexpected)")
    
    return results

def main():
    parser = argparse.ArgumentParser(description="Validate perimeter exposure")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--expected", required=True, help="Comma-separated list of expected open ports")
    parser.add_argument("--timeout", type=float, default=2.0)
    
    args = parser.parse_args()
    
    try:
        expected_ports = [int(p.strip()) for p in args.expected.split(",")]
        results = validate_perimeter(args.target, expected_ports)
        
        print(f"\n[*] Perimeter Validation Report for {args.target}")
        print(f"    Expected open & found: {len(results['compliant'])}")
        print(f"    Unexpected open: {len(results['unexpected'])}")
        print(f"    Risky ports open: {len(results['risk'])}")
        
        risk_level = "LOW" if not results['risk'] and not results['unexpected'] else "MEDIUM" if results['unexpected'] else "HIGH"
        print(f"    Risk Level: {risk_level}")
        
        if results['unexpected']:
            print(f"\n[!] Unexpected Open Ports: {', '.join(map(str, results['unexpected']))}")
        if results['risk']:
            print(f"\n[!] Risky Ports Open:")
            for port, msg in results['risk']:
                print(f"    {port}: {msg}")
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
