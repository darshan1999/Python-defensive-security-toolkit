#!/usr/bin/env python3
"""
Socket Validation Scanner - Validates socket connectivity from CSV file.
Checks each host:port and compares against expected status (open/closed).
"""

import argparse
import csv
import socket
import sys

class SocketValidationScanner:
    """Validates socket connectivity against expected firewall rules."""
    
    def __init__(self, timeout=3):
        self.timeout = timeout
        self.results = []
        self.passed = 0
        self.failed = 0
    
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
    
    def validate_csv(self, csv_file):
        """Validate connectivity from CSV file with format: host,port,expected_status"""
        print(f"\n[*] Loading CSV file: {csv_file}")
        
        try:
            with open(csv_file, 'r') as f:
                reader = csv.reader(f)
                
                header = next(reader, None)
                if header:
                    print(f"[*] CSV columns: {', '.join(header)}")
                
                print("\n" + "-" * 80)
                print(f"{'Host':<20} {'Port':<8} {'Expected':<12} {'Actual':<12} {'Result':<8} {'Status'}")
                print("-" * 80)
                
                for row_num, row in enumerate(reader, start=2):
                    if len(row) < 3:
                        print(f"[!] Row {row_num}: Skipped (insufficient columns)")
                        continue
                    
                    host = row[0].strip()
                    try:
                        port = int(row[1].strip())
                    except ValueError:
                        print(f"[!] Row {row_num}: Invalid port number")
                        continue
                    
                    expected_status = row[2].strip().lower()
                    
                    if expected_status not in ['open', 'closed']:
                        print(f"[!] Row {row_num}: Expected status must be 'open' or 'closed'")
                        continue
                    
                    is_open = self.check_port(host, port)
                    actual_status = "open" if is_open else "closed"
                    
                    expected_open = (expected_status == 'open')
                    passed = (is_open == expected_open)
                    
                    result_str = "✓ PASS" if passed else "✗ FAIL"
                    status_symbol = "✓" if passed else "✗"
                    
                    print(f"{host:<20} {port:<8} {expected_status:<12} {actual_status:<12} {status_symbol:<8} {result_str}")
                    
                    self.results.append({
                        'host': host,
                        'port': port,
                        'expected': expected_status,
                        'actual': actual_status,
                        'passed': passed
                    })
                    
                    if passed:
                        self.passed += 1
                    else:
                        self.failed += 1
        
        except FileNotFoundError:
            print(f"[-] CSV file not found: {csv_file}")
            return False
        except Exception as e:
            print(f"[-] Error reading CSV: {e}")
            return False
        
        print("-" * 80)
        return True
    
    def report(self):
        """Generate validation report."""
        total = self.passed + self.failed
        
        if total == 0:
            print("[!] No entries to validate")
            return
        
        pass_rate = (self.passed / total) * 100 if total > 0 else 0
        
        print(f"\n[+] Validation complete")
        print(f"[+] Results: {self.passed} passed, {self.failed} failed ({pass_rate:.1f}% pass rate)")
        
        if self.failed > 0:
            print(f"\n[!] Failed entries:")
            for result in self.results:
                if not result['passed']:
                    print(f"  - {result['host']}:{result['port']} (expected {result['expected']}, got {result['actual']})")

def main():
    parser = argparse.ArgumentParser(
        description='Validate socket connectivity from CSV file for firewall rule verification.'
    )
    parser.add_argument('csv_file', help='CSV file with format: host,port,expected_status')
    parser.add_argument('-t', '--timeout', type=int, default=3, help='Socket timeout in seconds (default: 3)')
    
    args = parser.parse_args()
    
    scanner = SocketValidationScanner(timeout=args.timeout)
    if scanner.validate_csv(args.csv_file):
        scanner.report()

if __name__ == "__main__":
    main()
