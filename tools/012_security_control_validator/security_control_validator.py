#!/usr/bin/env python3
"""
Security Control Validator - Validates expected security controls on a host.
Checks: SSH (22), Telnet (23), HTTP (80), SMB (445) for proper state.
"""

import argparse
import socket
import sys

class SecurityControlValidator:
    """Validates security controls on a target host."""
    
    def __init__(self, timeout=3):
        self.timeout = timeout
        self.results = {}
    
    def check_port(self, host, port, should_be_open):
        """Check if port matches expected state."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            is_open = (result == 0)
            status = "OPEN" if is_open else "CLOSED"
            expected = "OPEN" if should_be_open else "CLOSED"
            
            passed = (is_open == should_be_open)
            return {
                'status': status,
                'expected': expected,
                'passed': passed
            }
        except Exception as e:
            return {
                'status': 'ERROR',
                'expected': 'OPEN' if should_be_open else 'CLOSED',
                'passed': False,
                'error': str(e)
            }
    
    def check_http_redirect(self, host):
        """Check if HTTP port 80 redirects or is closed."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, 80))
            
            if result == 0:
                sock.sendall(b'HEAD / HTTP/1.0\r\nHost: ' + host.encode() + b'\r\n\r\n')
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                if '301' in response or '302' in response or '307' in response or '308' in response:
                    return {'status': 'REDIRECTS', 'passed': True}
                else:
                    return {'status': 'OPEN_NO_REDIRECT', 'passed': False}
            else:
                sock.close()
                return {'status': 'CLOSED', 'passed': True}
        except Exception as e:
            return {'status': 'ERROR', 'passed': False, 'error': str(e)}
    
    def validate_controls(self, host):
        """Run all security control checks."""
        print(f"\n[*] Validating security controls on {host}")
        print("-" * 60)
        
        controls = [
            {'name': 'SSH Remote Management', 'port': 22, 'should_be': True},
            {'name': 'Telnet (Legacy)', 'port': 23, 'should_be': False},
            {'name': 'HTTP with Redirect', 'port': 80, 'should_be': 'special'},
            {'name': 'SMB (External)', 'port': 445, 'should_be': False},
        ]
        
        for control in controls:
            name = control['name']
            
            if control['should_be'] == 'special':
                result = self.check_http_redirect(host)
                status = result['status']
                passed = result['passed']
            else:
                result = self.check_port(host, control['port'], control['should_be'])
                status = result['status']
                passed = result['passed']
            
            result_str = "✓ PASS" if passed else "✗ FAIL"
            print(f"{name:<30} | Port {control['port']:<5} | {status:<20} | {result_str}")
            
            self.results[name] = {
                'port': control['port'],
                'status': status,
                'passed': passed
            }
        
        print("-" * 60)
        passed_count = sum(1 for r in self.results.values() if r['passed'])
        total = len(self.results)
        print(f"[+] Results: {passed_count}/{total} controls passed")
        
        return self.results

def main():
    parser = argparse.ArgumentParser(
        description='Validate expected security controls on a host.'
    )
    parser.add_argument('host', help='Target hostname or IP address')
    parser.add_argument('-t', '--timeout', type=int, default=3, help='Socket timeout in seconds (default: 3)')
    
    args = parser.parse_args()
    
    validator = SecurityControlValidator(timeout=args.timeout)
    validator.validate_controls(args.host)

if __name__ == "__main__":
    main()
