#!/usr/bin/env python3
"""
File Size Threshold Alerter - Alert when files exceed size thresholds.

Recursively scans directory for files exceeding threshold (default 100MB).
Displays: file path, size in MB, last modified time, owner (Linux).
Flags files that have grown significantly vs stored state.
Maintains JSON state file for delta detection.
"""

import argparse
import os
import json
import pwd
from datetime import datetime
from pathlib import Path

class FileSizeThresholdAlerter:
    """Detects files exceeding size thresholds."""
    
    def __init__(self, threshold_mb=100, state_file=None):
        self.threshold_bytes = threshold_mb * 1024 * 1024
        self.state_file = state_file or '.filesize_state.json'
        self.previous_state = self._load_state()
        self.current_state = {}
        self.alerts = []
    
    def _load_state(self):
        """Load previous file state from JSON."""
        try:
            if os.path.exists(self.state_file):
                with open(self.state_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}
    
    def _save_state(self):
        """Save current state to JSON."""
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self.current_state, f, indent=2)
        except Exception as e:
            print(f"[!] Cannot save state file: {e}", flush=True)
    
    def get_file_owner(self, filepath):
        """Get file owner name (Linux/Mac)."""
        try:
            stat_info = os.stat(filepath)
            return pwd.getpwuid(stat_info.st_uid).pw_name
        except (KeyError, OSError):
            return "unknown"
    
    def scan_directory(self, directory):
        """Recursively scan for large files."""
        for root, dirs, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    size_bytes = os.path.getsize(filepath)
                    
                    if size_bytes > self.threshold_bytes:
                        size_mb = size_bytes / (1024 * 1024)
                        mtime = os.path.getmtime(filepath)
                        last_modified = datetime.fromtimestamp(mtime).isoformat()
                        owner = self.get_file_owner(filepath)
                        
                        # Check for significant growth
                        growth = 0
                        if filepath in self.previous_state:
                            prev_size = self.previous_state[filepath].get('size_bytes', 0)
                            growth = size_bytes - prev_size
                        
                        self.current_state[filepath] = {
                            'size_bytes': size_bytes,
                            'size_mb': round(size_mb, 2),
                            'last_modified': last_modified,
                            'owner': owner
                        }
                        
                        alert = {
                            'file': filepath,
                            'size_mb': round(size_mb, 2),
                            'size_bytes': size_bytes,
                            'last_modified': last_modified,
                            'owner': owner,
                            'growth_bytes': growth,
                            'growth_mb': round(growth / (1024 * 1024), 2) if growth > 0 else 0,
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        if growth > 0:
                            alert['flagged'] = True
                            alert['reason'] = f"Significant growth: {alert['growth_mb']}MB"
                        
                        self.alerts.append(alert)
                except (OSError, IOError) as e:
                    continue
        
        self.alerts.sort(key=lambda x: x['size_bytes'], reverse=True)
    
    def report(self):
        """Generate alert report."""
        self._save_state()
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'threshold_mb': self.threshold_bytes / (1024 * 1024),
            'total_files_exceeding': len(self.alerts),
            'flagged_for_growth': len([a for a in self.alerts if a.get('flagged')]),
            'files': self.alerts,
            'summary': f"Found {len(self.alerts)} files exceeding {self.threshold_bytes/(1024*1024):.0f}MB"
        }
        return report

def main():
    parser = argparse.ArgumentParser(
        description='Alert on files exceeding size threshold.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 file_size_threshold_alerter.py --directory /var/log --threshold 100
  python3 file_size_threshold_alerter.py --directory /home --threshold 500 --output alert.json
  python3 file_size_threshold_alerter.py --directory /app --threshold 50 --state mystate.json
        """)
    
    parser.add_argument('--directory', type=str, required=True, help='Directory to scan')
    parser.add_argument('--threshold', type=int, default=100, help='Size threshold in MB (default 100)')
    parser.add_argument('--output', type=str, help='Output JSON file')
    parser.add_argument('--state', type=str, help='State file path (default .filesize_state.json)')
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.directory):
        print(f"[!] Directory not found: {args.directory}")
        return
    
    alerter = FileSizeThresholdAlerter(
        threshold_mb=args.threshold,
        state_file=args.state
    )
    
    print(f"[*] Scanning {args.directory} for files > {args.threshold}MB...", flush=True)
    alerter.scan_directory(args.directory)
    
    report = alerter.report()
    
    import json
    print(json.dumps(report, indent=2))
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")

if __name__ == "__main__":
    main()
