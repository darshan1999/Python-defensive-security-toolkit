#!/usr/bin/env python3
"""
SIEM Dashboard Enhancer - Generate HTML dashboard from JSON log data.

Aggregates: top 10 IPs, event counts by type, by severity, timeline by hour.
Outputs self-contained HTML with tables and basic charts.
"""

import argparse
import json
from datetime import datetime, timedelta
from collections import defaultdict
import re

class SIEMDashboardEnhancer:
    """Generates HTML dashboards from security log data."""
    
    def __init__(self, json_file):
        self.data = self._load_json(json_file)
        self.stats = {}
    
    def _load_json(self, filepath):
        """Load JSON data."""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                return data if isinstance(data, list) else [data]
        except Exception as e:
            print(f"[!] Error loading JSON: {e}", flush=True)
            return []
    
    def analyze_data(self):
        """Analyze log data for dashboard."""
        ips = defaultdict(int)
        event_types = defaultdict(int)
        severities = defaultdict(int)
        timeline = defaultdict(int)
        
        for record in self.data:
            if not isinstance(record, dict):
                continue
            
            # Count IPs
            for key in ['ip', 'source_ip', 'src_ip', 'attacker_ip']:
                if key in record:
                    ips[record[key]] += 1
            
            # Count event types
            for key in ['type', 'event_type', 'action']:
                if key in record:
                    event_types[str(record[key])] += 1
            
            # Count severities
            for key in ['severity', 'level']:
                if key in record:
                    severities[str(record[key])] += 1
            
            # Timeline
            for key in ['timestamp', 'time']:
                if key in record:
                    try:
                        ts = datetime.fromisoformat(str(record[key]).replace('Z', '+00:00'))
                        hour = ts.strftime('%Y-%m-%d %H:00')
                        timeline[hour] += 1
                    except:
                        pass
        
        self.stats = {
            'total_records': len(self.data),
            'top_ips': sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10],
            'event_types': sorted(event_types.items(), key=lambda x: x[1], reverse=True),
            'severities': sorted(severities.items(), key=lambda x: x[1], reverse=True),
            'timeline': sorted(timeline.items())
        }
    
    def generate_html(self):
        """Generate HTML dashboard."""
        # Generate rows
        total = self.stats['total_records']
        if total == 0:
            total = 1
        
        ip_rows = ''.join([
            f"<tr><td>{ip}</td><td>{count}</td><td>{count/total*100:.1f}%</td></tr>"
            for ip, count in self.stats['top_ips']
        ])
        
        type_rows = ''.join([
            f"<tr><td>{et}</td><td>{count}</td><td>{count/total*100:.1f}%</td></tr>"
            for et, count in self.stats['event_types'][:10]
        ])
        
        severity_rows = ''.join([
            f"<tr><td><span class='severity-{sev.lower()}'>{sev}</span></td><td>{count}</td><td>{count/total*100:.1f}%</td></tr>"
            for sev, count in self.stats['severities']
        ])
        
        max_timeline = max([c for _, c in self.stats['timeline']], default=1)
        if max_timeline == 0:
            max_timeline = 1
        
        timeline_rows = ''.join([
            f"<tr><td>{hour}</td><td>{count}</td><td><div class='bar' style='width:{count/max_timeline*300}px'></div></td></tr>"
            for hour, count in self.stats['timeline']
        ])
        
        critical = sum(c for s, c in self.stats['severities'] if s.upper() == 'CRITICAL')
        
        timestamp = datetime.now().isoformat()
        unique_ips = len(self.stats['top_ips'])
        event_type_count = len(self.stats['event_types'])
        
        # Build HTML without using .format() on large template
        html = '<!DOCTYPE html>\n<html>\n<head>\n<meta charset="UTF-8">\n<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        html += '<title>Security Dashboard</title>\n<style>\n'
        html += 'body {font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5;}\n'
        html += '.header {background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px;}\n'
        html += '.container {max-width: 1200px; margin: 0 auto;}\n'
        html += '.section {background-color: white; padding: 20px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);}\n'
        html += '.section h2 {margin-top: 0; border-bottom: 2px solid #3498db; padding-bottom: 10px; color: #2c3e50;}\n'
        html += 'table {width: 100%; border-collapse: collapse; margin-top: 10px;}\n'
        html += 'th {background-color: #3498db; color: white; padding: 10px; text-align: left; font-weight: bold;}\n'
        html += 'tr {border-bottom: 1px solid #ddd;}\n'
        html += 'tr:hover {background-color: #f9f9f9;}\n'
        html += 'td {padding: 10px;}\n'
        html += '.metric {display: inline-block; margin: 10px 20px 10px 0; padding: 15px; background-color: #ecf0f1; border-radius: 5px; min-width: 200px;}\n'
        html += '.metric-value {font-size: 32px; font-weight: bold; color: #2c3e50;}\n'
        html += '.metric-label {color: #7f8c8d; font-size: 14px; margin-top: 5px;}\n'
        html += '.bar {display: inline-block; height: 20px; background-color: #3498db; margin: 5px 0; border-radius: 3px;}\n'
        html += '.severity-critical {background-color: #e74c3c; color: white; font-weight: bold;}\n'
        html += '.severity-high {background-color: #e67e22; color: white;}\n'
        html += '.severity-medium {background-color: #f39c12; color: white;}\n'
        html += '.severity-low {background-color: #27ae60; color: white;}\n'
        html += '.severity-info {background-color: #3498db; color: white;}\n'
        html += '.footer {margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; text-align: center; font-size: 12px;}\n'
        html += '</style>\n</head>\n<body>\n<div class="container">\n'
        html += '<div class="header"><h1>Security Analytics Dashboard</h1><p>Generated: ' + timestamp + '</p></div>\n'
        html += '<div class="section"><h2>Overview</h2>\n'
        html += f'<div class="metric"><div class="metric-value">{total}</div><div class="metric-label">Total Events</div></div>\n'
        html += f'<div class="metric"><div class="metric-value">{unique_ips}</div><div class="metric-label">Unique Source IPs</div></div>\n'
        html += f'<div class="metric"><div class="metric-value">{event_type_count}</div><div class="metric-label">Event Types</div></div>\n'
        html += f'<div class="metric"><div class="metric-value">{critical}</div><div class="metric-label">Critical Events</div></div>\n'
        html += '</div>\n<div class="section"><h2>Top 10 Source IPs</h2><table><tr><th>Source IP</th><th>Event Count</th><th>Percentage</th></tr>\n'
        html += ip_rows
        html += '</table></div>\n<div class="section"><h2>Events by Type</h2><table><tr><th>Event Type</th><th>Count</th><th>Percentage</th></tr>\n'
        html += type_rows
        html += '</table></div>\n<div class="section"><h2>Events by Severity</h2><table><tr><th>Severity</th><th>Count</th><th>Percentage</th></tr>\n'
        html += severity_rows
        html += '</table></div>\n<div class="section"><h2>Activity Timeline</h2><table><tr><th>Hour</th><th>Event Count</th><th>Graph</th></tr>\n'
        html += timeline_rows
        html += '</table></div>\n<div class="footer"><p>Security Dashboard Generated by SIEM Enhancer</p></div>\n</div>\n</body>\n</html>'
        
        return html
    
    def save_html(self, output_file):
        """Save HTML to file."""
        try:
            html = self.generate_html()
            with open(output_file, 'w') as f:
                f.write(html)
            print(f"[+] Dashboard saved to {output_file}")
        except Exception as e:
            print(f"[!] Error saving HTML: {e}", flush=True)

def main():
    parser = argparse.ArgumentParser(
        description='Generate HTML dashboard from security log data.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 siem_dashboard_enhancer.py --input alerts.json --output dashboard.html
  python3 siem_dashboard_enhancer.py --input logs.json --output report.html
        """)
    
    parser.add_argument('--input', type=str, required=True, help='Input JSON file')
    parser.add_argument('--output', type=str, required=True, help='Output HTML file')
    
    args = parser.parse_args()
    
    print(f"[*] Generating dashboard from {args.input}...", flush=True)
    
    enhancer = SIEMDashboardEnhancer(args.input)
    enhancer.analyze_data()
    enhancer.save_html(args.output)

if __name__ == "__main__":
    main()
