#!/usr/bin/env python3
"""
Correlation Alert Exporter - Export alerts to multiple formats.

Reads JSON correlation alerts. Exports to:
- Syslog (RFC 5424)
- CEF (Common Event Format)
- LEEF (Log Event Extended Format)
- JSON (pretty printed)

Supports --format flag or --all for all formats.
"""

import argparse
import json
from datetime import datetime
import socket

class CorrelationAlertExporter:
    """Exports correlation alerts to multiple formats."""
    
    def __init__(self, json_file):
        self.alerts = self._load_json(json_file)
    
    def _load_json(self, filepath):
        """Load JSON alerts."""
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Error loading JSON: {e}", flush=True)
            return []
    
    def export_syslog(self):
        """Export as RFC 5424 Syslog."""
        hostname = socket.gethostname()
        syslog_entries = []
        
        for alert in self.alerts:
            if isinstance(alert, dict):
                timestamp = alert.get('timestamp', datetime.now().isoformat())
                message = json.dumps(alert)
                
                # RFC 5424 format: <PRI>VERSION TIMESTAMP HOSTNAME TAG[PID]: MSG
                pri = 134  # (16 * 8) + 6 = Local0.Info
                syslog = f"<{pri}>1 {timestamp} {hostname} correlation-alert - - {message}"
                syslog_entries.append(syslog)
        
        return syslog_entries
    
    def export_cef(self):
        """Export as Common Event Format (CEF)."""
        cef_entries = []
        
        for idx, alert in enumerate(self.alerts):
            if isinstance(alert, dict):
                # CEF format: CEF:0|vendor|product|version|event_id|name|severity|extension
                timestamp = alert.get('timestamp', datetime.now().isoformat())
                
                extensions = {
                    'act': 'Correlation Detected',
                    'cs1Label': 'Correlation Type',
                    'cs1': alert.get('type', 'unknown'),
                    'dvc': socket.gethostname(),
                    'rt': timestamp,
                    'cs2Label': 'IPs',
                    'cs2': ','.join(alert.get('ips', [])) if isinstance(alert.get('ips'), list) else str(alert.get('ips', '')),
                    'cs3Label': 'Sources',
                    'cs3': ','.join(alert.get('sources', [])) if isinstance(alert.get('sources'), list) else str(alert.get('sources', ''))
                }
                
                ext_str = ' '.join([f"{k}={v}" for k, v in extensions.items()])
                
                severity = alert.get('severity', 'Medium')
                severity_num = {'LOW': 1, 'MEDIUM': 5, 'HIGH': 8, 'CRITICAL': 10}.get(severity.upper(), 5)
                
                cef = f"CEF:0|SecurityTeam|CorrelationEngine|1.0|{idx}|Correlation Alert|{severity_num}|{ext_str}"
                cef_entries.append(cef)
        
        return cef_entries
    
    def export_leef(self):
        """Export as Log Event Extended Format (LEEF)."""
        leef_entries = []
        
        for idx, alert in enumerate(self.alerts):
            if isinstance(alert, dict):
                # LEEF format: LEEF:1.0|vendor|product|version|event_id|key1=value1 key2=value2
                timestamp = alert.get('timestamp', datetime.now().isoformat())
                
                kv_pairs = {
                    'timestamp': timestamp,
                    'type': alert.get('type', 'unknown'),
                    'severity': alert.get('severity', 'Medium'),
                    'ip_count': len(alert.get('ips', [])),
                    'source_count': len(alert.get('sources', []))
                }
                
                kv_str = '\t'.join([f"{k}={v}" for k, v in kv_pairs.items()])
                
                leef = f"LEEF:1.0|SecurityTeam|CorrelationEngine|1.0|{idx}|{kv_str}"
                leef_entries.append(leef)
        
        return leef_entries
    
    def export_json(self):
        """Export as JSON."""
        return json.dumps(self.alerts, indent=2)
    
    def save_format(self, entries, output_file, format_name):
        """Save exported entries to file."""
        try:
            if format_name == 'json':
                content = entries
            else:
                content = '\n'.join(entries) if isinstance(entries, list) else entries
            
            with open(output_file, 'w') as f:
                f.write(content)
            
            print(f"[+] Exported {format_name.upper()} to {output_file}")
        except Exception as e:
            print(f"[!] Error saving {format_name}: {e}", flush=True)

def main():
    parser = argparse.ArgumentParser(
        description='Export correlation alerts to multiple formats.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 correlation_alert_exporter.py --input alerts.json --format syslog --output alerts.syslog
  python3 correlation_alert_exporter.py --input corr.json --format cef --output alerts.cef
  python3 correlation_alert_exporter.py --input alerts.json --all --output alerts_dir/
  python3 correlation_alert_exporter.py --input alerts.json --format leef --output alerts.leef
        """)
    
    parser.add_argument('--input', type=str, required=True, help='Input JSON file')
    parser.add_argument('--format', choices=['syslog', 'cef', 'leef', 'json'], help='Export format')
    parser.add_argument('--all', action='store_true', help='Export all formats')
    parser.add_argument('--output', type=str, help='Output file (for single format)')
    
    args = parser.parse_args()
    
    exporter = CorrelationAlertExporter(args.input)
    
    if args.all:
        base = args.output or 'alerts'
        exporter.save_format(exporter.export_syslog(), f"{base}.syslog", 'syslog')
        exporter.save_format(exporter.export_cef(), f"{base}.cef", 'cef')
        exporter.save_format(exporter.export_leef(), f"{base}.leef", 'leef')
        exporter.save_format(exporter.export_json(), f"{base}.json", 'json')
    elif args.format:
        if args.format == 'syslog':
            entries = exporter.export_syslog()
        elif args.format == 'cef':
            entries = exporter.export_cef()
        elif args.format == 'leef':
            entries = exporter.export_leef()
        else:
            entries = exporter.export_json()
        
        if args.output:
            exporter.save_format(entries, args.output, args.format)
        else:
            if isinstance(entries, list):
                for entry in entries:
                    print(entry)
            else:
                print(entries)
    else:
        # Default to JSON
        entries = exporter.export_json()
        if args.output:
            exporter.save_format(entries, args.output, 'json')
        else:
            print(entries)

if __name__ == "__main__":
    main()
