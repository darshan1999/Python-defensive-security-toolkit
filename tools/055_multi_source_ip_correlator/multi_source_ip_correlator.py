#!/usr/bin/env python3
"""
Multi-Source IP Correlator - Find same IP across multiple files.

Accepts multiple input files with IPs (one per line or CSV).
Finds IPs appearing in 2+ sources.
Reports: source files, occurrence count, first/last seen.
Ranks by source count. Outputs CSV.
"""

import argparse
import csv
import re
from datetime import datetime
from collections import defaultdict

class MultiSourceIPCorrelator:
    """Finds IPs appearing across multiple sources."""
    
    def __init__(self):
        self.ip_sources = defaultdict(lambda: {
            'sources': set(),
            'count': 0,
            'first_seen': None,
            'last_seen': None
        })
    
    def parse_file(self, filepath, source_name):
        """Parse file for IP addresses."""
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    
                    # Try to extract IPs
                    ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', line)
                    
                    # If no IPs found, try treating as CSV
                    if not ips and ',' in line:
                        parts = line.split(',')
                        for part in parts:
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', part)
                            if ip_match:
                                ips.append(ip_match.group(1))
                    
                    for ip in ips:
                        # Skip private IPs
                        if ip.startswith('127') or ip.startswith('192.168') or ip.startswith('10.'):
                            continue
                        
                        data = self.ip_sources[ip]
                        data['sources'].add(source_name)
                        data['count'] += 1
                        
                        if data['first_seen'] is None:
                            data['first_seen'] = datetime.now().isoformat()
                        data['last_seen'] = datetime.now().isoformat()
        
        except IOError as e:
            print(f"[!] Error reading {filepath}: {e}", flush=True)
    
    def find_correlations(self):
        """Find IPs appearing in multiple sources."""
        correlations = []
        
        for ip, data in self.ip_sources.items():
            if len(data['sources']) >= 2:
                correlations.append({
                    'ip': ip,
                    'source_count': len(data['sources']),
                    'sources': ','.join(sorted(data['sources'])),
                    'occurrence_count': data['count'],
                    'first_seen': data['first_seen'],
                    'last_seen': data['last_seen']
                })
        
        # Sort by source count (highest first)
        correlations.sort(key=lambda x: x['source_count'], reverse=True)
        
        return correlations
    
    def output_csv(self, correlations, output_file):
        """Output correlations as CSV."""
        try:
            with open(output_file, 'w', newline='') as f:
                fieldnames = ['ip', 'source_count', 'sources', 'occurrence_count', 'first_seen', 'last_seen']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                
                writer.writeheader()
                writer.writerows(correlations)
            
            print(f"[+] CSV saved to {output_file}")
        except IOError as e:
            print(f"[!] Error writing CSV: {e}", flush=True)

def main():
    parser = argparse.ArgumentParser(
        description='Find IPs appearing across multiple sources.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 multi_source_ip_correlator.py --file ips1.txt src1 --file ips2.txt src2 --output corr.csv
  python3 multi_source_ip_correlator.py --file auth.log auth --file firewall.log fw --file syslog sys
  python3 multi_source_ip_correlator.py --file blocked.csv blocked --file suspicious.txt susp --output multi_source.csv
        """)
    
    parser.add_argument('--file', nargs=2, action='append', metavar=('FILE', 'SOURCE'),
                       help='Input file and source name (use multiple times)')
    parser.add_argument('--output', type=str, default='multi_source_ips.csv', help='Output CSV file')
    
    args = parser.parse_args()
    
    if not args.file or len(args.file) < 2:
        print("[!] At least 2 input files required")
        parser.print_help()
        return
    
    correlator = MultiSourceIPCorrelator()
    
    for filepath, source_name in args.file:
        print(f"[*] Parsing {filepath} ({source_name})...", flush=True)
        correlator.parse_file(filepath, source_name)
    
    correlations = correlator.find_correlations()
    
    print(f"\n[+] Found {len(correlations)} IPs in multiple sources")
    
    for corr in correlations:
        print(f"  {corr['ip']}: {corr['source_count']} sources ({corr['sources']}) - {corr['occurrence_count']} occurrences")
    
    correlator.output_csv(correlations, args.output)

if __name__ == "__main__":
    main()
