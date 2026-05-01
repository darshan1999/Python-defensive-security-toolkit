#!/usr/bin/env python3
"""
Internal Network Mapper - Maps live hosts on local network using CIDR range.
Detects hostnames and open ports (22, 80, 443, 445, 3389) using threading.
"""

import argparse
import ipaddress
import socket
import threading
from datetime import datetime
from queue import Queue

class InternalNetworkMapper:
    """Maps live hosts on a network subnet using CIDR range."""
    
    def __init__(self, timeout=2, threads=20):
        self.timeout = timeout
        self.threads = threads
        self.results = {}
        self.lock = threading.Lock()
        self.ports = [22, 80, 443, 445, 3389]
    
    def scan_port(self, host, port):
        """Check if a port is open on target host."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except (socket.gaierror, socket.error):
            return False
    
    def get_hostname(self, ip):
        """Attempt to resolve hostname from IP address."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.error):
            return None
    
    def check_host(self, ip):
        """Check if host is alive and scan ports."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, 443))
            sock.close()
            
            if result != 0:
                result = sock.connect_ex((ip, 22))
                sock.close()
            
            if result == 0:
                hostname = self.get_hostname(ip)
                open_ports = [p for p in self.ports if self.scan_port(ip, p)]
                
                with self.lock:
                    self.results[ip] = {
                        'hostname': hostname or 'UNKNOWN',
                        'open_ports': open_ports,
                        'port_count': len(open_ports)
                    }
                print(f"[+] LIVE: {ip:<15} | Hostname: {hostname or 'UNKNOWN':<20} | Ports: {open_ports}")
        except Exception as e:
            pass
    
    def scan_network(self, cidr):
        """Scan network range using threading."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            print(f"[-] Invalid CIDR range: {e}")
            return False
        
        print(f"[*] Scanning network: {cidr}")
        print(f"[*] Total hosts: {network.num_addresses}")
        print(f"[*] Using {self.threads} threads")
        print("-" * 70)
        
        def worker():
            while True:
                ip = q.get()
                if ip is None:
                    break
                self.check_host(str(ip))
                q.task_done()
        
        q = Queue()
        thread_list = []
        
        for _ in range(self.threads):
            t = threading.Thread(target=worker)
            t.start()
            thread_list.append(t)
        
        for host in network.hosts():
            q.put(host)
        
        for _ in range(self.threads):
            q.put(None)
        
        for t in thread_list:
            t.join()
        
        return True
    
    def report(self):
        """Generate scan report."""
        print("-" * 70)
        print(f"[*] Scan complete. Found {len(self.results)} live hosts.")
        
        if self.results:
            print("\n[NETWORK MAP]")
            for ip in sorted(self.results.keys()):
                info = self.results[ip]
                ports_str = ','.join(map(str, info['open_ports'])) if info['open_ports'] else 'NONE'
                print(f"  {ip:<15} | {info['hostname']:<20} | Open Ports: {ports_str}")
        
        return self.results

def main():
    parser = argparse.ArgumentParser(
        description='Map live hosts on a local network subnet using CIDR range.'
    )
    parser.add_argument('cidr', help='CIDR range (e.g., 192.168.1.0/24)')
    parser.add_argument('-t', '--timeout', type=int, default=2, help='Socket timeout in seconds (default: 2)')
    parser.add_argument('-j', '--threads', type=int, default=20, help='Number of threads (default: 20)')
    
    args = parser.parse_args()
    
    mapper = InternalNetworkMapper(timeout=args.timeout, threads=args.threads)
    if mapper.scan_network(args.cidr):
        mapper.report()

if __name__ == "__main__":
    main()
