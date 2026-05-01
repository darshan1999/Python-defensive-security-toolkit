#!/usr/bin/env python3
"""
Service Enumeration Tool - Enumerates services on target.
Tests top 20 common ports and attempts banner grabbing.
"""

import argparse
import socket
import time

class ServiceEnumerationTool:
    """Enumerates services running on target host."""
    
    # Common ports and their typical services
    COMMON_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        135: 'RPC',
        139: 'NetBIOS',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        1723: 'PPTP',
        3306: 'MySQL',
        3389: 'RDP',
        5900: 'VNC',
        8080: 'HTTP-Alt',
    }
    
    def __init__(self, timeout=3):
        self.timeout = timeout
        self.services = {}
    
    def grab_banner(self, host, port, service_name):
        """Attempt to grab service banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            banner = b''
            try:
                banner = sock.recv(1024)
            except socket.timeout:
                pass
            
            sock.close()
            
            if banner:
                banner_str = banner.decode('utf-8', errors='ignore').strip()
                return banner_str
            return None
        except Exception:
            return None
    
    def identify_service(self, host, port, service_name, banner):
        """Identify service based on port, name, and banner."""
        if banner:
            lower_banner = banner.lower()
            
            if 'ssh' in lower_banner:
                return 'SSH', banner[:50]
            elif 'http' in lower_banner or '200 ok' in lower_banner:
                return 'HTTP', banner[:50]
            elif 'ftp' in lower_banner:
                return 'FTP', banner[:50]
            elif 'smtp' in lower_banner or 'mail' in lower_banner:
                return 'SMTP', banner[:50]
            elif 'mysql' in lower_banner:
                return 'MySQL', banner[:50]
            elif 'microsoft sql' in lower_banner:
                return 'MSSQL', banner[:50]
            else:
                return service_name, banner[:50]
        
        return service_name, None
    
    def scan_services(self, host):
        """Scan target for running services."""
        print(f"\n[*] Enumerating services on {host}")
        print("-" * 85)
        print(f"{'Port':<6} {'Service':<15} {'Status':<8} {'Banner':<50}")
        print("-" * 85)
        
        for port in sorted(self.COMMON_PORTS.keys()):
            service_name = self.COMMON_PORTS[port]
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    status = "OPEN"
                    status_symbol = "✓"
                    
                    banner = self.grab_banner(host, port, service_name)
                    service, banner_snippet = self.identify_service(host, port, service_name, banner)
                    
                    banner_display = banner_snippet if banner_snippet else "(no banner)"
                    
                    print(f"{port:<6} {service:<15} {status_symbol} {status:<7} {banner_display:<50}")
                    
                    self.services[port] = {
                        'service': service,
                        'status': 'open',
                        'banner': banner_snippet
                    }
            except Exception as e:
                pass
        
        print("-" * 85)
        return self.services
    
    def report(self):
        """Generate enumeration report."""
        print(f"\n[+] Enumeration complete")
        print(f"[+] Found {len(self.services)} open services")
        
        if self.services:
            print(f"\n[SERVICES DETECTED]")
            for port in sorted(self.services.keys()):
                info = self.services[port]
                banner = info['banner'] if info['banner'] else '(no banner)'
                print(f"  {port:<6} - {info['service']:<15} | {banner}")

def main():
    parser = argparse.ArgumentParser(
        description='Enumerate services on target host with banner grabbing.'
    )
    parser.add_argument('host', help='Target hostname or IP address')
    parser.add_argument('-t', '--timeout', type=int, default=3, help='Socket timeout in seconds (default: 3)')
    
    args = parser.parse_args()
    
    tool = ServiceEnumerationTool(timeout=args.timeout)
    tool.scan_services(args.host)
    tool.report()

if __name__ == "__main__":
    main()
