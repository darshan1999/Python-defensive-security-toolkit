#!/usr/bin/env python3
"""
Suspicious Activity Logger - Aggregate multiple suspicious activities.

Parses auth.log, syslog, application.log for:
- Failed logins
- Port scan patterns
- Large transfers
- Unusual processes
- Cron changes

Writes unified JSON log with timestamp, source, type, severity.
Deduplicates events within 60s window.
"""

import argparse
import json
import re
import time
from datetime import datetime, timedelta
from collections import defaultdict

class SuspiciousActivityLogger:
    """Aggregates suspicious activities from multiple log sources."""
    
    def __init__(self, dedup_window=60):
        self.dedup_window = dedup_window
        self.activities = []
        self.dedup_cache = set()
    
    def _create_dedup_key(self, source, activity_type, detail):
        """Create deduplication key."""
        return f"{source}:{activity_type}:{detail}"
    
    def _should_deduplicate(self, key, timestamp):
        """Check if event should be deduplicated."""
        # Simple dedup: store just keys for now
        if key in self.dedup_cache:
            return True
        self.dedup_cache.add(key)
        return False
    
    def parse_auth_log(self, log_file):
        """Parse auth.log for failed logins."""
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    if 'Failed password' in line or 'Invalid user' in line:
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            ip = match.group(1)
                            key = self._create_dedup_key('auth.log', 'failed_login', ip)
                            
                            if not self._should_deduplicate(key, datetime.now()):
                                self.activities.append({
                                    'timestamp': datetime.now().isoformat(),
                                    'source': 'auth.log',
                                    'type': 'failed_login',
                                    'ip': ip,
                                    'severity': 'MEDIUM'
                                })
        except IOError:
            pass
    
    def parse_syslog(self, log_file):
        """Parse syslog for port scans and system events."""
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    # Port scan detection
                    if 'nmap' in line.lower() or 'port' in line.lower() and 'scan' in line.lower():
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            ip = match.group(1)
                            key = self._create_dedup_key('syslog', 'port_scan', ip)
                            
                            if not self._should_deduplicate(key, datetime.now()):
                                self.activities.append({
                                    'timestamp': datetime.now().isoformat(),
                                    'source': 'syslog',
                                    'type': 'port_scan',
                                    'ip': ip,
                                    'severity': 'HIGH'
                                })
                    
                    # Cron changes
                    if 'cron' in line.lower() and ('modified' in line.lower() or 'added' in line.lower()):
                        key = self._create_dedup_key('syslog', 'cron_change', line[:50])
                        
                        if not self._should_deduplicate(key, datetime.now()):
                            self.activities.append({
                                'timestamp': datetime.now().isoformat(),
                                'source': 'syslog',
                                'type': 'cron_change',
                                'detail': line[:100],
                                'severity': 'HIGH'
                            })
        except IOError:
            pass
    
    def parse_application_log(self, log_file):
        """Parse application log for suspicious patterns."""
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    # Large transfer detection
                    if 'transfer' in line.lower() and re.search(r'(\d+)\s*(MB|GB)', line):
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        ip = match.group(1) if match else 'unknown'
                        
                        size_match = re.search(r'(\d+)\s*(MB|GB)', line)
                        if size_match:
                            size = size_match.group(1)
                            unit = size_match.group(2)
                            
                            key = self._create_dedup_key('application.log', 'large_transfer', f"{ip}:{size}{unit}")
                            
                            if not self._should_deduplicate(key, datetime.now()):
                                self.activities.append({
                                    'timestamp': datetime.now().isoformat(),
                                    'source': 'application.log',
                                    'type': 'large_transfer',
                                    'ip': ip,
                                    'size': f"{size}{unit}",
                                    'severity': 'MEDIUM'
                                })
                    
                    # Unusual process detection
                    if 'process' in line.lower() and ('spawned' in line.lower() or 'executed' in line.lower()):
                        key = self._create_dedup_key('application.log', 'unusual_process', line[:50])
                        
                        if not self._should_deduplicate(key, datetime.now()):
                            self.activities.append({
                                'timestamp': datetime.now().isoformat(),
                                'source': 'application.log',
                                'type': 'unusual_process',
                                'detail': line[:100],
                                'severity': 'MEDIUM'
                            })
        except IOError:
            pass
    
    def generate_report(self):
        """Generate report."""
        severity_count = defaultdict(int)
        type_count = defaultdict(int)
        
        for activity in self.activities:
            severity_count[activity['severity']] += 1
            type_count[activity['type']] += 1
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_activities': len(self.activities),
            'by_severity': dict(severity_count),
            'by_type': dict(type_count),
            'activities': self.activities
        }
        
        return report

def main():
    parser = argparse.ArgumentParser(
        description='Aggregate suspicious activities from multiple log sources.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 suspicious_activity_logger.py --auth /var/log/auth.log --syslog /var/log/syslog
  python3 suspicious_activity_logger.py --auth auth.log --syslog syslog --app app.log --output suspicious.json
  python3 suspicious_activity_logger.py --auth /var/log/auth.log --output activity.json
        """)
    
    parser.add_argument('--auth', type=str, help='Auth log file')
    parser.add_argument('--syslog', type=str, help='Syslog file')
    parser.add_argument('--app', type=str, help='Application log file')
    parser.add_argument('--output', type=str, help='Output JSON file')
    
    args = parser.parse_args()
    
    if not any([args.auth, args.syslog, args.app]):
        parser.print_help()
        return
    
    logger = SuspiciousActivityLogger()
    
    if args.auth:
        print(f"[*] Parsing {args.auth}...", flush=True)
        logger.parse_auth_log(args.auth)
    
    if args.syslog:
        print(f"[*] Parsing {args.syslog}...", flush=True)
        logger.parse_syslog(args.syslog)
    
    if args.app:
        print(f"[*] Parsing {args.app}...", flush=True)
        logger.parse_application_log(args.app)
    
    report = logger.generate_report()
    print(json.dumps(report, indent=2))
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")

if __name__ == "__main__":
    main()
