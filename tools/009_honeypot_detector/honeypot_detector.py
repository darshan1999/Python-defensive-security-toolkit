#!/usr/bin/env python3
"""
Honeypot Detector - Identifies potential honeypot characteristics on target hosts.
Checks for: abnormally fast responses, excessive open ports, non-standard service responses.
"""

import sys
import socket
import argparse
from datetime import datetime

def check_response_time(host: str, port: int, timeout: float = 1.0) -> float:
    """Measure response time for a port connection attempt."""
    start = datetime.now()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
    except:
        pass
    elapsed = (datetime.now() - start).total_seconds()
    return elapsed

def check_service_response(host: str, port: int, timeout: float = 2.0) -> str:
    """Try to grab banner from service."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        data = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        return data[:100]
    except:
        return ""

def scan_ports(host: str, port_range: range = range(1, 1025)) -> list:
    """Scan for open ports."""
    open_ports = []
    for port in port_range:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((host, port)) == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

def detect_honeypot(host: str) -> dict:
    """Analyze target for honeypot characteristics."""
    results = {
        'open_ports': [],
        'response_times': {},
        'service_responses': {},
        'score': 0,
        'indicators': []
    }
    
    print(f"[*] Scanning {host} for honeypot characteristics...")
    
    # Check common ports
    common_ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080]
    open_ports = []
    response_times = []
    
    for port in common_ports:
        if socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect_ex((host, port)) == 0:
            open_ports.append(port)
            resp_time = check_response_time(host, port)
            response_times.append(resp_time)
            results['response_times'][port] = resp_time
            
            # Try to grab banner
            banner = check_service_response(host, port)
            results['service_responses'][port] = banner
            if not banner:
                results['indicators'].append(f"Port {port} open but no banner response")
    
    results['open_ports'] = open_ports
    
    # Analyze for honeypot indicators
    if len(open_ports) > 7:  # Too many ports open is suspicious
        results['score'] += 30
        results['indicators'].append(f"Unusually high number of open ports: {len(open_ports)}")
    
    if response_times and all(t < 0.05 for t in response_times):  # All responses too fast
        results['score'] += 25
        results['indicators'].append("All ports respond extremely fast (potential honeypot)")
    
    if any(not results['service_responses'].get(p) for p in open_ports):  # Some ports don't banner
        results['score'] += 15
        results['indicators'].append("Some ports open but don't provide service banners")
    
    # Classify likelihood
    if results['score'] >= 60:
        results['likelihood'] = "HIGH"
    elif results['score'] >= 30:
        results['likelihood'] = "MEDIUM"
    else:
        results['likelihood'] = "LOW"
    
    return results

def main():
    parser = argparse.ArgumentParser(
        description="Detect honeypot characteristics on a target host"
    )
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--timeout", type=float, default=2.0, help="Connection timeout")
    
    args = parser.parse_args()
    
    try:
        results = detect_honeypot(args.target)
        
        print(f"\n[*] Analysis for {args.target}")
        print(f"    Open ports: {', '.join(map(str, results['open_ports'])) or 'None'}")
        print(f"    Response time: {sum(results['response_times'].values()) / len(results['response_times'].values()):.3f}s avg" if results['response_times'] else "    Response time: N/A")
        print(f"    Honeypot likelihood: {results['likelihood']} (score: {results['score']}/100)")
        
        if results['indicators']:
            print("\n[!] Suspicious Indicators:")
            for ind in results['indicators']:
                print(f"    - {ind}")
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
