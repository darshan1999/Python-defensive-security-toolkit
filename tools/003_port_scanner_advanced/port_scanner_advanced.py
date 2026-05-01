#!/usr/bin/env python3
"""Advanced Port Scanner with multi-threading and service detection"""

import socket
import threading
import sys
from datetime import datetime
from queue import Queue

class AdvancedPortScanner:
    """Advanced port scanner with threading"""
    
    def __init__(self, host, threads=10):
        self.host = host
        self.threads = threads
        self.queue = Queue()
        self.open_ports = []
        self.lock = threading.Lock()
    
    def scan_port(self, port):
        """Scan single port"""
        try:
            socket.setdefaulttimeout(1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((self.host, port))
            sock.close()
            
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
                print(f"[+] Port {port}: OPEN")
        except Exception:
            pass
    
    def worker(self):
        """Worker thread function"""
        while True:
            port = self.queue.get()
            if port is None:
                break
            self.scan_port(port)
            self.queue.task_done()
    
    def scan_range(self, start_port, end_port):
        """Scan port range with threading"""
        print(f"[*] Scanning {self.host} ports {start_port}-{end_port} with {self.threads} threads")
        print(f"[*] Start time: {datetime.now().isoformat()}")
        
        # Queue ports
        for port in range(start_port, end_port + 1):
            self.queue.put(port)
        
        # Start workers
        thread_list = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.start()
            thread_list.append(t)
        
        # Wait for completion
        self.queue.join()
        for _ in range(self.threads):
            self.queue.put(None)
        for t in thread_list:
            t.join()
        
        return self.open_ports

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python3 port_scanner_advanced.py <host> [start_port] [end_port] [threads]")
        print("Example: python3 port_scanner_advanced.py 192.168.1.1 1 10000 20")
        sys.exit(1)
    
    host = sys.argv[1]
    start_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end_port = int(sys.argv[3]) if len(sys.argv) > 3 else 65535
    threads = int(sys.argv[4]) if len(sys.argv) > 4 else 20
    
    scanner = AdvancedPortScanner(host, threads)
    open_ports = scanner.scan_range(start_port, end_port)
    
    print(f"\n[*] End time: {datetime.now().isoformat()}")
    print(f"[+] Found {len(open_ports)} open ports: {open_ports}")

if __name__ == "__main__":
    main()
