#!/usr/bin/env python3
"""
Off-Hours Activity Detector - Detect SSH activity outside business hours.

Parses auth.log for successful logins (Accepted password/key).
Compares against business hours (default Mon-Fri 08:00-18:00).
Flags activity outside hours with username, IP, time, day.
"""

import argparse
import json
import re
from datetime import datetime
from collections import defaultdict

class OffHoursActivityDetector:
    """Detects off-hours SSH activity."""
    
    WEEKDAY_NAMES = {0: 'Monday', 1: 'Tuesday', 2: 'Wednesday', 3: 'Thursday', 4: 'Friday', 5: 'Saturday', 6: 'Sunday'}
    
    def __init__(self, business_days='0-4', business_hours='08:00-18:00'):
        # Parse business days (e.g., "0-4" = Monday-Friday)
        parts = business_days.split('-')
        self.business_start_day = int(parts[0])
        self.business_end_day = int(parts[1]) if len(parts) > 1 else int(parts[0])
        
        # Parse business hours (e.g., "08:00-18:00")
        hparts = business_hours.split('-')
        self.business_start_hour = int(hparts[0].split(':')[0])
        self.business_end_hour = int(hparts[1].split(':')[0])
        
        self.logins = []
        self.off_hours_logins = []
    
    def is_business_hours(self, dt):
        """Check if datetime is during business hours."""
        weekday = dt.weekday()
        hour = dt.hour
        
        # Check if within business days
        if not (self.business_start_day <= weekday <= self.business_end_day):
            return False
        
        # Check if within business hours
        if not (self.business_start_hour <= hour < self.business_end_hour):
            return False
        
        return True
    
    def parse_auth_log(self, log_file):
        """Parse auth.log for successful logins."""
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    # Parse Accepted password
                    if 'Accepted password' in line or 'Accepted key' in line:
                        match = re.search(r'(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+.*?(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            date_str = match.group(1)
                            username = match.group(2)
                            ip = match.group(3)
                            
                            # Parse timestamp (Month Day HH:MM:SS)
                            try:
                                # Add current year if not present
                                dt = datetime.strptime(f"{datetime.now().year} {date_str}", "%Y %b %d %H:%M:%S")
                                
                                login = {
                                    'username': username,
                                    'ip': ip,
                                    'timestamp': dt.isoformat(),
                                    'day_of_week': self.WEEKDAY_NAMES[dt.weekday()],
                                    'hour': dt.hour,
                                    'during_business_hours': self.is_business_hours(dt)
                                }
                                
                                self.logins.append(login)
                                
                                # Flag off-hours logins
                                if not login['during_business_hours']:
                                    self.off_hours_logins.append(login)
                            except ValueError:
                                continue
        
        except IOError as e:
            print(f"[!] Error reading log: {e}", flush=True)
    
    def generate_report(self):
        """Generate report."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'business_hours': f"{self.business_start_hour:02d}:00-{self.business_end_hour:02d}:00",
            'business_days': f"{self.WEEKDAY_NAMES[self.business_start_day]}-{self.WEEKDAY_NAMES[self.business_end_day]}",
            'total_logins': len(self.logins),
            'business_hours_logins': len(self.logins) - len(self.off_hours_logins),
            'off_hours_logins': len(self.off_hours_logins),
            'suspicious_activities': self.off_hours_logins
        }
        
        return report

def main():
    parser = argparse.ArgumentParser(
        description='Detect off-hours SSH activity.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 off_hours_activity_detector.py --log /var/log/auth.log
  python3 off_hours_activity_detector.py --log auth.log --output off_hours.json
  python3 off_hours_activity_detector.py --log auth.log --business-days 0-4 --business-hours 08:00-18:00
  python3 off_hours_activity_detector.py --log auth.log --business-days 0-6 --business-hours 09:00-17:00
        """)
    
    parser.add_argument('--log', type=str, required=True, help='Auth log file')
    parser.add_argument('--business-days', type=str, default='0-4', help='Business days (0-4 = Mon-Fri)')
    parser.add_argument('--business-hours', type=str, default='08:00-18:00', help='Business hours (HH:MM-HH:MM)')
    parser.add_argument('--output', type=str, help='Output JSON file')
    
    args = parser.parse_args()
    
    detector = OffHoursActivityDetector(args.business_days, args.business_hours)
    
    print(f"[*] Analyzing {args.log}...", flush=True)
    detector.parse_auth_log(args.log)
    
    report = detector.generate_report()
    print(json.dumps(report, indent=2))
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")

if __name__ == "__main__":
    main()
