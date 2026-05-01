#!/usr/bin/env python3
"""
Threaded Multi-Port Scanner - High-speed threaded port scanner.
Uses threading.Thread and queue.Queue with progress tracking.
"""

import argparse
import socket
import sys
import threading
import time
from queue import Queue

class ThreadedMultiPortScanner:
    """High-speed multi-threaded port scanner."""
    
    def __init__(self, threads=50, timeout=2):
        self.threads_count = threads
        self.timeout = timeout
        self.open_ports = []
        self.scanned_ports = 0
        self.lock = threading.Lock()
        self.start_time = None
        self.end_time = None
    
    def scan_port(self, host, port):
        """Check if single port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except (socket.gaierror, socket.error):
            return False
    
    def worker(self, host, port_queue, total_ports):
        """Worker thread function."""
        while True:
            port = port_queue.get()
            
            if port is None:
                break
            
            if self.scan_port(host, port):
                with self.lock:
                    self.open_ports.append(port)
                    print(f"[+] Port {port:<6} OPEN")
            
            with self.lock:
                self.scanned_ports += 1
                if self.scanned_ports % 50 == 0 or self.scanned_ports == total_ports:
                    progress = (self.scanned_ports / total_ports) * 100
                    print(f"[*] Progress: {self.scanned_ports}/{total_ports} ports ({progress:.1f}%)")
            
            port_queue.task_done()
    
    def scan_target(self, host, port_range):
        """Scan single target host."""
        start_port, end_port = port_range
        total_ports = end_port - start_port + 1
        
        print(f"\n[*] Starting scan on {host}")
        print(f"[*] Port range: {start_port}-{end_port} ({total_ports} ports)")
        print(f"[*] Threads: {self.threads_count} | Timeout: {self.timeout}s")
        print("-" * 60)
        
        self.start_time = time.time()
        self.scanned_ports = 0
        self.open_ports = []
        
        port_queue = Queue()
        threads = []
        
        for _ in range(self.threads_count):
            t = threading.Thread(target=self.worker, args=(host, port_queue, total_ports))
            t.start()
            threads.append(t)
        
        for port in range(start_port, end_port + 1):
            port_queue.put(port)
        
        for _ in range(self.threads_count):
            port_queue.put(None)
        
        for t in threads:
            t.join()
        
        self.end_time = time.time()
    
    def scan_targets_from_file(self, file_path, port_range):
        """Scan multiple targets from file."""
        try:
            with open(file_path, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[-] File not found: {file_path}")
            return False
        
        if not targets:
            print(f"[-] No targets found in file")
            return False
        
        print(f"[*] Loaded {len(targets)} targets from {file_path}")
        
        for target in targets:
            self.scan_target(target, port_range)
            self.report_target()
        
        return True
    
    def report_target(self):
        """Report results for current target."""
        elapsed_time = self.end_time - self.start_time
        
        print("-" * 60)
        print(f"[+] Scan complete")
        print(f"[+] Open ports: {len(self.open_ports)}")
        print(f"[+] Scan time: {elapsed_time:.2f} seconds")
        
        if self.open_ports:
            print(f"\n[OPEN PORTS]")
            for port in sorted(self.open_ports):
                print(f"  {port}")
        
        ports_per_sec = self.scanned_ports / elapsed_time if elapsed_time > 0 else 0
        print(f"[+] Speed: {ports_per_sec:.0f} ports/second")

def main():
    parser = argparse.ArgumentParser(
        description='High-speed threaded port scanner for single or multiple targets.'
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('target', nargs='?', help='Single target hostname or IP')
    group.add_argument('-f', '--file', help='File with targets (one per line)')
    
    parser.add_argument('-p', '--ports', default='1-65535', 
                        help='Port range as start-end (default: 1-65535)')
    parser.add_argument('-j', '--threads', type=int, default=50,
                        help='Number of threads (default: 50)')
    parser.add_argument('-t', '--timeout', type=int, default=2,
                        help='Socket timeout in seconds (default: 2)')
    
    args = parser.parse_args()
    
    try:
        start_port, end_port = map(int, args.ports.split('-'))
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError("Invalid port range")
    except (ValueError, AttributeError):
        print("[-] Invalid port range (use format: start-end, e.g., 1-1000)")
        sys.exit(1)
    
    scanner = ThreadedMultiPortScanner(threads=args.threads, timeout=args.timeout)
    
    if args.file:
        scanner.scan_targets_from_file(args.file, (start_port, end_port))
    else:
        scanner.scan_target(args.target, (start_port, end_port))
        scanner.report_target()

if __name__ == "__main__":
    main()
