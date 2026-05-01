#!/usr/bin/env python3
"""
/var/www Monitor - Monitor web directory for web shell indicators.

Tracks new PHP/JSP/ASP files, modifications, and scans for suspicious patterns.
Alerts immediately on changes. Maintains baseline for delta detection.
"""

import argparse
import os
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

class VarWwwMonitor:
    """Monitors /var/www for web shell indicators."""
    
    WEB_EXTENSIONS = {'.php', '.php3', '.php4', '.php5', '.jsp', '.jspx', '.asp', '.aspx'}
    
    SHELL_PATTERNS = [
        (r'system\s*\(', 'system() function'),
        (r'exec\s*\(', 'exec() function'),
        (r'shell_exec\s*\(', 'shell_exec() function'),
        (r'passthru\s*\(', 'passthru() function'),
        (r'eval\s*\(', 'eval() function'),
        (r'base64_decode\s*\(', 'base64_decode() function'),
        (r'_REQUEST', '_REQUEST array access'),
        (r'_GET\s*\[', '_GET array access'),
        (r'_POST\s*\[', '_POST array access'),
    ]
    
    def __init__(self, directory, baseline_file='.www_baseline.json'):
        self.directory = directory
        self.baseline_file = baseline_file
        self.baseline = self._load_baseline()
        self.current = {}
        self.alerts = []
    
    def _load_baseline(self):
        """Load previous baseline."""
        try:
            if os.path.exists(self.baseline_file):
                with open(self.baseline_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}
    
    def _save_baseline(self):
        """Save current state."""
        try:
            with open(self.baseline_file, 'w') as f:
                json.dump(self.current, f, indent=2)
        except Exception as e:
            print(f"[!] Cannot save baseline: {e}", flush=True)
    
    def get_file_hash(self, filepath):
        """Calculate file hash."""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (IOError, OSError):
            return None
    
    def scan_file_for_shells(self, filepath):
        """Scan file for shell patterns."""
        suspicious = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                for pattern, description in self.SHELL_PATTERNS:
                    if re.search(pattern, content):
                        suspicious.append(description)
        except Exception:
            pass
        
        return suspicious
    
    def scan_directory(self):
        """Scan web directory."""
        for root, dirs, files in os.walk(self.directory):
            for file in files:
                if Path(file).suffix.lower() in self.WEB_EXTENSIONS:
                    filepath = os.path.join(root, file)
                    file_hash = self.get_file_hash(filepath)
                    
                    if file_hash:
                        self.current[filepath] = {
                            'hash': file_hash,
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        # Detect new file
                        if filepath not in self.baseline:
                            self.alerts.append({
                                'type': 'NEW_FILE',
                                'path': filepath,
                                'timestamp': datetime.now().isoformat()
                            })
                            
                            # Scan new file for shells
                            suspicious = self.scan_file_for_shells(filepath)
                            if suspicious:
                                self.alerts.append({
                                    'type': 'SHELL_PATTERN',
                                    'path': filepath,
                                    'patterns': suspicious,
                                    'timestamp': datetime.now().isoformat()
                                })
                        
                        # Detect modification
                        elif self.baseline[filepath]['hash'] != file_hash:
                            self.alerts.append({
                                'type': 'MODIFIED_FILE',
                                'path': filepath,
                                'timestamp': datetime.now().isoformat()
                            })
                            
                            # Scan modified file
                            suspicious = self.scan_file_for_shells(filepath)
                            if suspicious:
                                self.alerts.append({
                                    'type': 'SHELL_PATTERN',
                                    'path': filepath,
                                    'patterns': suspicious,
                                    'timestamp': datetime.now().isoformat()
                                })
        
        self._save_baseline()
    
    def report(self):
        """Generate report."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'directory': self.directory,
            'total_alerts': len(self.alerts),
            'alerts': self.alerts,
            'summary': f"Found {len(self.alerts)} security alerts"
        }
        return report

def main():
    parser = argparse.ArgumentParser(
        description='Monitor web directory for shell indicators.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 var_www_monitor.py --directory /var/www
  python3 var_www_monitor.py --directory /var/www/html --output alert.json
  python3 var_www_monitor.py --directory /app/web --baseline web_baseline.json
        """)
    
    parser.add_argument('--directory', type=str, default='/var/www', help='Web directory (default /var/www)')
    parser.add_argument('--output', type=str, help='Output JSON file')
    parser.add_argument('--baseline', type=str, help='Baseline file')
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.directory):
        print(f"[!] Directory not found: {args.directory}")
        return
    
    monitor = VarWwwMonitor(args.directory, args.baseline or '.www_baseline.json')
    
    print(f"[*] Monitoring {args.directory}...", flush=True)
    monitor.scan_directory()
    
    report = monitor.report()
    print(json.dumps(report, indent=2))
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")

if __name__ == "__main__":
    main()
