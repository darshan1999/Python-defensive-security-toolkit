#!/usr/bin/env python3
"""
Multi-Source Log Correlator - Correlate events across multiple log sources.

Finds same IP in multiple log sources within time window (default 5 min).
Flags correlation severity:
- SINGLE_SOURCE: Low priority
- DUAL_SOURCE: Medium priority  
- MULTI_SOURCE (3+): High priority
"""

import argparse
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict

class MultiSourceLogCorrelator:
    """Correlates events across multiple log sources."""
    
    def __init__(self, time_window_minutes=5):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.events = []
        self.correlations = []
    
    def parse_log(self, log_file, source_name):
        """Parse log file for IPs."""
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    # Extract IP addresses
                    ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', line)
                    
                    for ip in ips:
                        # Skip private IPs
                        if ip.startswith('127') or ip.startswith('192.168') or ip.startswith('10.'):
                            continue
                        
                        self.events.append({
                            'source': source_name,
                            'ip': ip,
                            'timestamp': datetime.now(),
                            'line': line[:100]
                        })
        except IOError as e:
            print(f"[!] Error reading {log_file}: {e}", flush=True)
    
    def correlate_events(self):
        """Find correlated events across sources."""
        # Group by IP
        ip_events = defaultdict(list)
        
        for event in self.events:
            ip_events[event['ip']].append(event)
        
        # Analyze correlations
        for ip, events in ip_events.items():
            if len(events) < 2:
                continue
            
            # Group by source
            sources = set(e['source'] for e in events)
            
            if len(sources) >= 2:
                # Calculate time span
                timestamps = sorted([e['timestamp'] for e in events])
                time_span = timestamps[-1] - timestamps[0]
                
                # Check if within window
                if time_span <= self.time_window:
                    severity = 'LOW'
                    if len(sources) >= 3:
                        severity = 'HIGH'
                    elif len(sources) == 2:
                        severity = 'MEDIUM'
                    
                    self.correlations.append({
                        'ip': ip,
                        'source_count': len(sources),
                        'sources': list(sources),
                        'severity': severity,
                        'event_count': len(events),
                        'time_span_seconds': int(time_span.total_seconds()),
                        'events': [{
                            'source': e['source'],
                            'timestamp': e['timestamp'].isoformat()
                        } for e in events]
                    })
        
        # Sort by severity
        severity_rank = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        self.correlations.sort(key=lambda x: severity_rank.get(x['severity'], 3))
    
    def generate_report(self):
        """Generate correlation report."""
        high_severity = len([c for c in self.correlations if c['severity'] == 'HIGH'])
        medium_severity = len([c for c in self.correlations if c['severity'] == 'MEDIUM'])
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_events': len(self.events),
            'total_unique_ips': len(set(e['ip'] for e in self.events)),
            'correlations_found': len(self.correlations),
            'high_severity': high_severity,
            'medium_severity': medium_severity,
            'correlated_ips': self.correlations
        }
        
        return report

def main():
    parser = argparse.ArgumentParser(
        description='Correlate events across multiple log sources.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 multi_source_log_correlator.py --log auth.log auth --log syslog sys --output corr.json
  python3 multi_source_log_correlator.py --log auth.log auth --log firewall.log fw --log app.log app
  python3 multi_source_log_correlator.py --log a.log src1 --log b.log src2 --window 10
        """)
    
    parser.add_argument('--log', nargs=2, action='append', metavar=('FILE', 'SOURCE'),
                       help='Log file and source name (use multiple times)')
    parser.add_argument('--window', type=int, default=5, help='Time window in minutes (default 5)')
    parser.add_argument('--output', type=str, help='Output JSON file')
    
    args = parser.parse_args()
    
    if not args.log:
        parser.print_help()
        return
    
    correlator = MultiSourceLogCorrelator(time_window_minutes=args.window)
    
    for log_file, source_name in args.log:
        print(f"[*] Parsing {log_file} ({source_name})...", flush=True)
        correlator.parse_log(log_file, source_name)
    
    correlator.correlate_events()
    
    report = correlator.generate_report()
    print(json.dumps(report, indent=2))
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")

if __name__ == "__main__":
    main()
