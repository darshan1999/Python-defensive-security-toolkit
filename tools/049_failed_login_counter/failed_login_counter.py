#!/usr/bin/env python3
"""
Failed Login Counter - Count failed login attempts from auth.log.

Parses "Failed password" and "Invalid user" entries.
Groups by IP and username.
Flags IPs: >10=HIGH, >5=MEDIUM, >2=LOW.
Outputs JSON report with severity levels.
"""

import argparse
import json
import re
from datetime import datetime
from collections import defaultdict

class FailedLoginCounter:
    """Analyzes failed login attempts."""
    
    def __init__(self):
        self.ip_stats = defaultdict(lambda: {
            'failed_count': 0,
            'usernames': defaultdict(int),
            'first_seen': None,
            'last_seen': None
        })
        self.username_stats = defaultdict(lambda: {
            'failed_count': 0,
            'ips': defaultdict(int),
            'first_seen': None,
            'last_seen': None
        })
    
    def parse_auth_log(self, log_file):
        """Parse auth.log for failed login attempts."""
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    timestamp = datetime.now().isoformat()
                    
                    # Parse Failed password
                    if 'Failed password' in line:
                        match = re.search(r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            username = match.group(1)
                            ip = match.group(2)
                            
                            self._record_failure(ip, username, timestamp)
                    
                    # Parse Invalid user
                    elif 'Invalid user' in line:
                        match = re.search(r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            username = match.group(1)
                            ip = match.group(2)
                            
                            self._record_failure(ip, username, timestamp)
        
        except IOError as e:
            print(f"[!] Error reading log: {e}", flush=True)
    
    def _record_failure(self, ip, username, timestamp):
        """Record a failed login."""
        ip_stat = self.ip_stats[ip]
        ip_stat['failed_count'] += 1
        ip_stat['usernames'][username] += 1
        if ip_stat['first_seen'] is None:
            ip_stat['first_seen'] = timestamp
        ip_stat['last_seen'] = timestamp
        
        user_stat = self.username_stats[username]
        user_stat['failed_count'] += 1
        user_stat['ips'][ip] += 1
        if user_stat['first_seen'] is None:
            user_stat['first_seen'] = timestamp
        user_stat['last_seen'] = timestamp
    
    def get_severity(self, count):
        """Determine severity level."""
        if count > 10:
            return 'HIGH'
        elif count > 5:
            return 'MEDIUM'
        elif count > 2:
            return 'LOW'
        else:
            return 'INFO'
    
    def generate_report(self):
        """Generate report."""
        ip_report = []
        
        for ip, stats in self.ip_stats.items():
            ip_report.append({
                'source_ip': ip,
                'failed_attempts': stats['failed_count'],
                'unique_usernames': len(stats['usernames']),
                'targeted_usernames': dict(stats['usernames']),
                'severity': self.get_severity(stats['failed_count']),
                'first_seen': stats['first_seen'],
                'last_seen': stats['last_seen']
            })
        
        user_report = []
        
        for username, stats in self.username_stats.items():
            user_report.append({
                'username': username,
                'failed_attempts': stats['failed_count'],
                'attacking_ips': len(stats['ips']),
                'ip_sources': dict(stats['ips']),
                'severity': self.get_severity(stats['failed_count']),
                'first_seen': stats['first_seen'],
                'last_seen': stats['last_seen']
            })
        
        # Sort by count
        ip_report.sort(key=lambda x: x['failed_attempts'], reverse=True)
        user_report.sort(key=lambda x: x['failed_attempts'], reverse=True)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_unique_ips': len(self.ip_stats),
            'total_unique_usernames': len(self.username_stats),
            'total_failed_attempts': sum(s['failed_count'] for s in self.ip_stats.values()),
            'by_source_ip': ip_report,
            'by_username': user_report
        }
        
        return report

def main():
    parser = argparse.ArgumentParser(
        description='Count failed login attempts from auth.log.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 failed_login_counter.py --log /var/log/auth.log
  python3 failed_login_counter.py --log auth.log --output report.json
  python3 failed_login_counter.py --log /var/log/secure --output failed_logins.json
        """)
    
    parser.add_argument('--log', type=str, required=True, help='Auth log file')
    parser.add_argument('--output', type=str, help='Output JSON file')
    
    args = parser.parse_args()
    
    counter = FailedLoginCounter()
    
    print(f"[*] Analyzing {args.log}...", flush=True)
    counter.parse_auth_log(args.log)
    
    report = counter.generate_report()
    print(json.dumps(report, indent=2))
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")

if __name__ == "__main__":
    main()
