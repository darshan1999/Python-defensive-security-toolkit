#!/usr/bin/env python3
"""
Multi-IP User Detector - Detect users logging in from multiple IPs.

Parses auth.log for successful logins.
Groups by username, flags users with >2 IPs within time window (default 1 hour).
Reports username, IPs, timestamps, time deltas between logins.
"""

import argparse
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict

class MultiIPUserDetector:
    """Detects users logging in from multiple IPs."""
    
    def __init__(self, time_window_hours=1):
        self.time_window = timedelta(hours=time_window_hours)
        self.user_logins = defaultdict(list)
        self.suspicious_users = []
    
    def parse_auth_log(self, log_file):
        """Parse auth.log for successful logins."""
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    # Look for Accepted password or Accepted key
                    if 'Accepted password' in line or 'Accepted key' in line or 'Accepted publickey' in line:
                        # Extract username and IP
                        match = re.search(r'(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            username = match.group(1)
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
                            
                            self.user_logins[username].append({
                                'ip': ip,
                                'timestamp': dt
                            })
        except IOError as e:
            print(f"[!] Error reading log: {e}", flush=True)
    
    def analyze_users(self):
        """Analyze user login patterns."""
        for username, logins in self.user_logins.items():
            # Sort by timestamp
            logins.sort(key=lambda x: x['timestamp'])
            
            # Check for multiple IPs within time window
            for i in range(len(logins)):
                window_start = logins[i]['timestamp']
                window_end = window_start + self.time_window
                
                # Find logins within window
                logins_in_window = [
                    login for login in logins 
                    if window_start <= login['timestamp'] <= window_end
                ]
                
                unique_ips = set(login['ip'] for login in logins_in_window)
                
                if len(unique_ips) > 2:
                    # Calculate time deltas
                    times = sorted([login['timestamp'] for login in logins_in_window])
                    deltas = []
                    for j in range(len(times) - 1):
                        delta = (times[j+1] - times[j]).total_seconds()
                        deltas.append(delta)
                    
                    suspicious_entry = {
                        'username': username,
                        'unique_ips': len(unique_ips),
                        'ips': list(unique_ips),
                        'login_count_in_window': len(logins_in_window),
                        'time_deltas_seconds': deltas,
                        'window_start': window_start.isoformat(),
                        'window_end': window_end.isoformat(),
                        'logins': [
                            {
                                'ip': login['ip'],
                                'timestamp': login['timestamp'].isoformat()
                            }
                            for login in logins_in_window
                        ],
                        'severity': 'HIGH' if len(unique_ips) > 3 else 'MEDIUM'
                    }
                    
                    # Check if this is a duplicate
                    if not any(s['username'] == username and s['ips'] == suspicious_entry['ips'] 
                              for s in self.suspicious_users):
                        self.suspicious_users.append(suspicious_entry)
    
    def generate_report(self):
        """Generate report."""
        high_severity = len([u for u in self.suspicious_users if u['severity'] == 'HIGH'])
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'time_window_hours': self.time_window.total_seconds() / 3600,
            'total_users_analyzed': len(self.user_logins),
            'suspicious_users_found': len(self.suspicious_users),
            'high_severity_count': high_severity,
            'suspicious_users': self.suspicious_users
        }
        
        return report

def main():
    parser = argparse.ArgumentParser(
        description='Detect users logging in from multiple IPs.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 multi_ip_user_detector.py --log /var/log/auth.log
  python3 multi_ip_user_detector.py --log auth.log --window 2 --output multi_ip_users.json
  python3 multi_ip_user_detector.py --log /var/log/auth.log --window 1 --output report.json
        """)
    
    parser.add_argument('--log', type=str, required=True, help='Auth log file')
    parser.add_argument('--window', type=int, default=1, help='Time window in hours (default 1)')
    parser.add_argument('--output', type=str, help='Output JSON file')
    
    args = parser.parse_args()
    
    detector = MultiIPUserDetector(time_window_hours=args.window)
    
    print(f"[*] Analyzing {args.log}...", flush=True)
    detector.parse_auth_log(args.log)
    detector.analyze_users()
    
    report = detector.generate_report()
    print(json.dumps(report, indent=2))
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")

if __name__ == "__main__":
    main()
