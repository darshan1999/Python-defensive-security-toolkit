#!/usr/bin/env python3
"""Basic Port Scanner for defensive network assessment"""

import socket
import sys
from datetime import datetime

def scan_port(host, port, timeout=2):
    """Scan a single port"""
    try:
        socket.setdefaulttimeout(timeout)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception as e:
        return False

def scan_host(host, ports):
    """Scan multiple ports on a host"""
    print(f"[*] Starting scan on {host} at {datetime.now().isoformat()}")
    print(f"[*] Scanning {len(ports)} ports...")
    print("-" * 50)
    
    open_ports = []
    for port in ports:
        if scan_port(host, port):
            open_ports.append(port)
            print(f"[+] Port {port}: OPEN")
        else:
            print(f"[-] Port {port}: CLOSED")
    
    print("-" * 50)
    print(f"[*] Scan complete. Open ports: {len(open_ports)}")
    return open_ports

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python3 port_scanner_basic.py <host> [port1,port2,...]")
        print("Example: python3 port_scanner_basic.py 192.168.1.1 80,443,22")
        sys.exit(1)
    
    host = sys.argv[1]
    
    # Default common ports
    default_ports = [22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
    
    # Use custom ports if provided
    if len(sys.argv) > 2:
        try:
            ports = [int(p.strip()) for p in sys.argv[2].split(",")]
        except ValueError:
            print("[!] Invalid port specification")
            sys.exit(1)
    else:
        ports = default_ports
    
    open_ports = scan_host(host, ports)
    
    if open_ports:
        print(f"\n[+] Results: {open_ports}")
    else:
        print("\n[-] No open ports found")

if __name__ == "__main__":
    main()
