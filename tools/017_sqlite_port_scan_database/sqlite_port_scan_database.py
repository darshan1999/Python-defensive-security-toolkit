#!/usr/bin/env python3
"""
SQLite Port Scan Database - Stores port scan results in SQLite database.
Tracks changes between scans and reports new/closed ports.
"""

import argparse
import sqlite3
import socket
import sys
from datetime import datetime

class SqlitePortScanDatabase:
    """Manages port scan results in SQLite database."""
    
    def __init__(self, db_file='port_scans.db', timeout=3):
        self.db_file = db_file
        self.timeout = timeout
        self.conn = None
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with scan results table."""
        try:
            self.conn = sqlite3.connect(self.db_file)
            cursor = self.conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS port_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    target_ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    service TEXT,
                    UNIQUE(timestamp, target_ip, port)
                )
            ''')
            
            self.conn.commit()
            print(f"[+] Database initialized: {self.db_file}")
        except sqlite3.Error as e:
            print(f"[-] Database error: {e}")
            sys.exit(1)
    
    def check_port(self, host, port):
        """Check if port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def get_service_name(self, port):
        """Get common service name for port."""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
            1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt'
        }
        return services.get(port, 'Unknown')
    
    def scan_ports(self, target_ip, ports):
        """Scan target ports and store results."""
        timestamp = datetime.now().isoformat()
        print(f"\n[*] Scanning {target_ip} on ports: {ports}")
        print("-" * 60)
        
        cursor = self.conn.cursor()
        scan_results = []
        
        for port in ports:
            is_open = self.check_port(target_ip, port)
            status = "open" if is_open else "closed"
            service = self.get_service_name(port) if is_open else None
            
            status_symbol = "✓" if is_open else "✗"
            print(f"Port {port:<6} | {status:<8} | {self.get_service_name(port):<15} {status_symbol}")
            
            try:
                cursor.execute('''
                    INSERT INTO port_scans (timestamp, target_ip, port, status, service)
                    VALUES (?, ?, ?, ?, ?)
                ''', (timestamp, target_ip, port, status, service))
                
                scan_results.append({
                    'port': port,
                    'status': status,
                    'service': service
                })
            except sqlite3.IntegrityError:
                pass
        
        self.conn.commit()
        print("-" * 60)
        
        return timestamp, scan_results
    
    def compare_scans(self, target_ip):
        """Compare current scan with previous scan and report changes."""
        cursor = self.conn.cursor()
        
        cursor.execute('''
            SELECT DISTINCT timestamp FROM port_scans 
            WHERE target_ip = ? 
            ORDER BY timestamp DESC LIMIT 2
        ''', (target_ip,))
        
        timestamps = cursor.fetchall()
        
        if len(timestamps) < 2:
            print(f"\n[*] No previous scan to compare (first scan for {target_ip})")
            return
        
        current_ts = timestamps[0][0]
        previous_ts = timestamps[1][0]
        
        cursor.execute('''
            SELECT port, status FROM port_scans 
            WHERE target_ip = ? AND timestamp = ?
        ''', (target_ip, current_ts))
        current = {row[0]: row[1] for row in cursor.fetchall()}
        
        cursor.execute('''
            SELECT port, status FROM port_scans 
            WHERE target_ip = ? AND timestamp = ?
        ''', (target_ip, previous_ts))
        previous = {row[0]: row[1] for row in cursor.fetchall()}
        
        print(f"\n[SCAN COMPARISON]")
        print(f"Previous scan: {previous_ts}")
        print(f"Current scan:  {current_ts}")
        print("-" * 60)
        
        new_open = []
        new_closed = []
        
        for port in current:
            if port not in previous:
                if current[port] == 'open':
                    new_open.append(port)
            elif previous[port] == 'closed' and current[port] == 'open':
                new_open.append(port)
            elif previous[port] == 'open' and current[port] == 'closed':
                new_closed.append(port)
        
        if new_open:
            print(f"[!] NEW OPEN PORTS: {new_open}")
        if new_closed:
            print(f"[+] NEWLY CLOSED PORTS: {new_closed}")
        
        if not new_open and not new_closed:
            print(f"[+] No changes detected")
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()

def main():
    parser = argparse.ArgumentParser(
        description='Store port scan results in SQLite database with change tracking.'
    )
    parser.add_argument('target_ip', help='Target IP address to scan')
    parser.add_argument('-p', '--ports', type=str, default='22,80,443,445,3389,3306,1433',
                        help='Comma-separated ports to scan (default: 22,80,443,445,3389,3306,1433)')
    parser.add_argument('-d', '--database', default='port_scans.db', help='SQLite database file')
    parser.add_argument('-t', '--timeout', type=int, default=3, help='Socket timeout in seconds')
    parser.add_argument('--compare', action='store_true', help='Compare with previous scan')
    
    args = parser.parse_args()
    
    try:
        ports = [int(p.strip()) for p in args.ports.split(',')]
    except ValueError:
        print("[-] Invalid port list")
        sys.exit(1)
    
    db = SqlitePortScanDatabase(db_file=args.database, timeout=args.timeout)
    
    timestamp, results = db.scan_ports(args.target_ip, ports)
    
    if args.compare:
        db.compare_scans(args.target_ip)
    
    db.close()

if __name__ == "__main__":
    main()
