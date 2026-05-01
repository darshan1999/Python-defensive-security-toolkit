#!/usr/bin/env python3
"""
Failed Login Admin Access Detector - Detect suspicious admin login attempts.

Flags admin accounts: root, admin, administrator, sudo, wheel.
Alerts:
- Any root attempt from external IP: CRITICAL
- >3 admin failures from same IP in 10 min: HIGH
- Admin from new IP: MEDIUM
"""

import argparse
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict

class FailedLoginAdminAccessDetector:
    """Detects suspicious admin account login attempts."""
    
    ADMIN_ACCOUNTS = {'root', 'admin', 'administrator', 'sudo', 'wheel'}
    
    def __init__(self, time_window_minutes=10):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.failed_attempts = []
        self.alerts = []
        self.known_ips = set()
    
    def parse_auth_log(self, log_file):
        """Parse auth.log for failed admin logins."""
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    if 'Failed password' in line or 'Invalid user' in line:
                        # Extract username and IP
                        match = re.search(r'(?:Failed password for |Invalid user )(\S+).*from (\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            username = match.group(1).strip()
                            ip = match.group(2)
                            
                            # Parse timestamp
                            dt_match = re.search(r'(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})', line)
                            if dt_match:
                                try:
                                    dt = datetime.strptime(f"{datetime.now().year} {dt_match.group(1)}", "%Y %b %d %H:%M:%S")
                                except ValueError:
                                    dt = datetime.now()
                            else:
                                dt = datetime.now()
                            
                            if username in self.ADMIN_ACCOUNTS:
                                self.failed_attempts.append({
                                    'username': username,
                                    'ip': ip,
                                    'timestamp': dt
                                })
        except IOError as e:
            print(f"[!] Error reading log: {e}", flush=True)
    
    def analyze_attempts(self):
        """Analyze failed admin attempts."""
        # Group by IP
        ip_attempts = defaultdict(list)
        
        for attempt in self.failed_attempts:
            ip_attempts[attempt['ip']].append(attempt)
        
        for ip, attempts in ip_attempts.items():
            is_external = not (ip.startswith('127') or ip.startswith('192.168') or ip.startswith('10.'))
            
            for attempt in attempts:
                # Check for root attempts from external IP
                if attempt['username'] == 'root' and is_external:
                    self.alerts.append({
                        'type': 'ROOT_ACCESS_ATTEMPT',
                        'severity': 'CRITICAL',
                        'username': attempt['username'],
                        'ip': ip,
                        'is_external': True,
                        'timestamp': attempt['timestamp'].isoformat()
                    })
            
            # Check for multiple failures from same IP in time window
            recent_attempts = [a for a in attempts if (a['timestamp'] - attempts[0]['timestamp']) <= self.time_window]
            
            if len(recent_attempts) >= 3:
                self.alerts.append({
                    'type': 'MULTIPLE_ADMIN_FAILURES',
                    'severity': 'HIGH',
                    'ip': ip,
                    'failure_count': len(recent_attempts),
                    'usernames_targeted': list(set(a['username'] for a in recent_attempts)),
                    'time_window_minutes': self.time_window.total_seconds() / 60,
                    'timestamp': datetime.now().isoformat()
                })
            
            # Check for new IP attempting admin access
            if is_external and ip not in self.known_ips:
                self.known_ips.add(ip)
                
                self.alerts.append({
                    'type': 'ADMIN_FROM_NEW_IP',
                    'severity': 'MEDIUM',
                    'ip': ip,
                    'is_external': True,
                    'timestamp': datetime.now().isoformat()
                })
    
    def generate_report(self):
        """Generate report."""
        severity_count = defaultdict(int)
        
        for alert in self.alerts:
            severity_count[alert['severity']] += 1
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_failed_admin_attempts': len(self.failed_attempts),
            'total_alerts': len(self.alerts),
            'by_severity': dict(severity_count),
            'alerts': self.alerts
        }
        
        return report

def main():
    parser = argparse.ArgumentParser(
        description='Detect suspicious admin account login attempts.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 failed_login_admin_access_detector.py --log /var/log/auth.log
  python3 failed_login_admin_access_detector.py --log auth.log --output admin_alert.json
  python3 failed_login_admin_access_detector.py --log /var/log/auth.log --window 15 --output alert.json
        """)
    
    parser.add_argument('--log', type=str, required=True, help='Auth log file')
    parser.add_argument('--window', type=int, default=10, help='Time window in minutes (default 10)')
    parser.add_argument('--output', type=str, help='Output JSON file')
    
    args = parser.parse_args()
    
    detector = FailedLoginAdminAccessDetector(time_window_minutes=args.window)
    
    print(f"[*] Analyzing {args.log}...", flush=True)
    detector.parse_auth_log(args.log)
    detector.analyze_attempts()
    
    report = detector.generate_report()
    print(json.dumps(report, indent=2))
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")

if __name__ == "__main__":
    main()
