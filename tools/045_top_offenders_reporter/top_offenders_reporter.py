#!/usr/bin/env python3
"""
Top Offenders Reporter - Analyze logs for top offender source IPs.

Counts events per source IP. Calculates:
- Total events
- Unique targets
- First/last seen timestamps
- Event types

Ranks by total events. Outputs top N (default 20) with formatted table.
"""

import argparse
import json
import re
from datetime import datetime
from collections import defaultdict

class TopOffendersReporter:
    """Analyzes logs for top source IPs."""
    
    def __init__(self):
        self.ip_stats = defaultdict(lambda: {
            'count': 0,
            'targets': set(),
            'first_seen': None,
            'last_seen': None,
            'event_types': defaultdict(int)
        })
    
    def parse_log(self, log_file):
        """Parse log file for IP patterns."""
        ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
        
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    # Extract IP addresses
                    ips = re.findall(ip_pattern, line)
                    
                    if ips:
                        source_ip = ips[0]
                        
                        # Try to extract target (second IP if present)
                        if len(ips) > 1:
                            target = ips[1]
                        else:
                            target = 'unknown'
                        
                        # Determine event type
                        event_type = 'unknown'
                        if 'Failed password' in line or 'Invalid user' in line:
                            event_type = 'failed_login'
                        elif 'Accepted password' in line or 'Accepted key' in line:
                            event_type = 'successful_login'
                        elif 'port scan' in line.lower() or 'nmap' in line.lower():
                            event_type = 'port_scan'
                        elif 'connection' in line.lower():
                            event_type = 'connection'
                        
                        # Update stats
                        stats = self.ip_stats[source_ip]
                        stats['count'] += 1
                        stats['targets'].add(target)
                        stats['event_types'][event_type] += 1
                        
                        # Update timestamps
                        timestamp = datetime.now().isoformat()
                        if stats['first_seen'] is None:
                            stats['first_seen'] = timestamp
                        stats['last_seen'] = timestamp
        
        except IOError as e:
            print(f"[!] Error reading log: {e}", flush=True)
            return
    
    def generate_report(self, top_n=20):
        """Generate top offenders report."""
        offenders = []
        
        for ip, stats in self.ip_stats.items():
            risk_level = 'LOW'
            if stats['count'] > 100:
                risk_level = 'CRITICAL'
            elif stats['count'] > 50:
                risk_level = 'HIGH'
            elif stats['count'] > 20:
                risk_level = 'MEDIUM'
            
            offenders.append({
                'source_ip': ip,
                'total_events': stats['count'],
                'unique_targets': len(stats['targets']),
                'event_types': dict(stats['event_types']),
                'first_seen': stats['first_seen'],
                'last_seen': stats['last_seen'],
                'risk_level': risk_level
            })
        
        # Sort by event count
        offenders.sort(key=lambda x: x['total_events'], reverse=True)
        offenders = offenders[:top_n]
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_unique_ips': len(self.ip_stats),
            'top_offenders_count': len(offenders),
            'offenders': offenders,
            'summary': f"Top {len(offenders)} offenders from {len(self.ip_stats)} unique IPs"
        }
        
        return report
    
    def print_table(self, report):
        """Print formatted table."""
        print(f"\n{'='*100}")
        print(f"TOP OFFENDERS REPORT")
        print(f"{'='*100}")
        print(f"{report['summary']}\n")
        
        print(f"{'Rank':<5} {'Source IP':<15} {'Events':<10} {'Targets':<10} {'Risk':<10} {'Last Seen':<20}")
        print(f"{'-'*100}")
        
        for idx, offender in enumerate(report['offenders'], 1):
            last_seen = offender['last_seen'].split('T')[1][:8] if offender['last_seen'] else 'N/A'
            print(f"{idx:<5} {offender['source_ip']:<15} {offender['total_events']:<10} "
                  f"{offender['unique_targets']:<10} {offender['risk_level']:<10} {last_seen:<20}")

def main():
    parser = argparse.ArgumentParser(
        description='Analyze logs for top offender source IPs.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 top_offenders_reporter.py --log auth.log --top 20
  python3 top_offenders_reporter.py --log syslog --top 50 --output report.json
  python3 top_offenders_reporter.py --log firewall.log --top 10 --output offenders.json --table
        """)
    
    parser.add_argument('--log', type=str, required=True, help='Log file to analyze')
    parser.add_argument('--top', type=int, default=20, help='Number of top offenders (default 20)')
    parser.add_argument('--output', type=str, help='Output JSON file')
    parser.add_argument('--table', action='store_true', help='Print formatted table')
    
    args = parser.parse_args()
    
    reporter = TopOffendersReporter()
    
    print(f"[*] Analyzing {args.log}...", flush=True)
    reporter.parse_log(args.log)
    
    report = reporter.generate_report(args.top)
    print(json.dumps(report, indent=2))
    
    if args.table:
        reporter.print_table(report)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")

if __name__ == "__main__":
    main()
