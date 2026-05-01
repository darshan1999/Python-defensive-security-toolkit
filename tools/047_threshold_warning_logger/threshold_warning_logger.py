#!/usr/bin/env python3
"""
Threshold Warning Logger - Monitor metrics and log threshold breaches.

Accepts metric name, current value, warning threshold, critical threshold.
Reads CSV of readings and generates summary.
Logs: timestamp, metric, value, status (OK/WARNING/CRITICAL), threshold.
"""

import argparse
import csv
import json
from datetime import datetime
from collections import defaultdict

class ThresholdWarningLogger:
    """Monitors metrics against thresholds."""
    
    def __init__(self, metric_name, warning_threshold, critical_threshold):
        self.metric_name = metric_name
        self.warning_threshold = warning_threshold
        self.critical_threshold = critical_threshold
        self.readings = []
        self.alerts = []
    
    def parse_csv(self, csv_file):
        """Parse CSV file with readings."""
        try:
            with open(csv_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        # Try common column names
                        timestamp = row.get('timestamp') or row.get('time') or datetime.now().isoformat()
                        
                        # Find value column
                        value = None
                        for key in ['value', 'val', self.metric_name]:
                            if key in row and row[key]:
                                value = float(row[key])
                                break
                        
                        if value is not None:
                            self.readings.append({
                                'timestamp': timestamp,
                                'value': value
                            })
                    except (ValueError, KeyError):
                        continue
        except IOError as e:
            print(f"[!] Error reading CSV: {e}", flush=True)
    
    def check_reading(self, value):
        """Check reading against thresholds."""
        if value >= self.critical_threshold:
            return 'CRITICAL'
        elif value >= self.warning_threshold:
            return 'WARNING'
        else:
            return 'OK'
    
    def process_readings(self):
        """Process all readings and generate alerts."""
        for reading in self.readings:
            status = self.check_reading(reading['value'])
            
            alert = {
                'timestamp': reading['timestamp'],
                'metric': self.metric_name,
                'value': reading['value'],
                'status': status,
                'warning_threshold': self.warning_threshold,
                'critical_threshold': self.critical_threshold
            }
            
            if status != 'OK':
                self.alerts.append(alert)
    
    def generate_summary(self):
        """Generate summary statistics."""
        if not self.readings:
            return {}
        
        values = [r['value'] for r in self.readings]
        
        critical_count = len([a for a in self.alerts if a['status'] == 'CRITICAL'])
        warning_count = len([a for a in self.alerts if a['status'] == 'WARNING'])
        
        summary = {
            'timestamp': datetime.now().isoformat(),
            'metric': self.metric_name,
            'total_readings': len(self.readings),
            'min_value': min(values),
            'max_value': max(values),
            'avg_value': sum(values) / len(values),
            'critical_alerts': critical_count,
            'warning_alerts': warning_count,
            'ok_readings': len(self.readings) - critical_count - warning_count,
            'thresholds': {
                'warning': self.warning_threshold,
                'critical': self.critical_threshold
            },
            'alerts': self.alerts
        }
        
        return summary

def main():
    parser = argparse.ArgumentParser(
        description='Monitor metrics and log threshold breaches.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 threshold_warning_logger.py --metric cpu --csv readings.csv --warning 75 --critical 90
  python3 threshold_warning_logger.py --metric memory --csv mem.csv --warning 80 --critical 95 --output alert.json
  python3 threshold_warning_logger.py --metric disk --csv disk_readings.csv --warning 85 --critical 95 --log thresholds.log
        """)
    
    parser.add_argument('--metric', type=str, required=True, help='Metric name')
    parser.add_argument('--csv', type=str, required=True, help='CSV file with readings')
    parser.add_argument('--warning', type=float, required=True, help='Warning threshold')
    parser.add_argument('--critical', type=float, required=True, help='Critical threshold')
    parser.add_argument('--output', type=str, help='Output JSON file')
    parser.add_argument('--log', type=str, help='Log file for alerts')
    
    args = parser.parse_args()
    
    logger = ThresholdWarningLogger(args.metric, args.warning, args.critical)
    
    print(f"[*] Processing {args.csv}...", flush=True)
    logger.parse_csv(args.csv)
    logger.process_readings()
    
    summary = logger.generate_summary()
    print(json.dumps(summary, indent=2))
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(summary, f, indent=2)
        print(f"[+] Report saved to {args.output}")
    
    if args.log:
        with open(args.log, 'a') as f:
            for alert in logger.alerts:
                f.write(json.dumps(alert) + '\n')
        print(f"[+] Alerts logged to {args.log}")

if __name__ == "__main__":
    main()
