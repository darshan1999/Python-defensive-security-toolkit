#!/usr/bin/env python3
"""
PHP/EXE Creation Alerter - Alert on creation of executable scripts.

Monitors for new .php, .py, .sh, .pl, .rb files.
Maintains baseline with file hashes.
Detects newly created/modified scripts and checks for suspicious patterns.
"""

import argparse
import os
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

class PhpExeCreationAlerter:
    """Detects creation and modification of executable scripts."""
    
    EXECUTABLE_EXTENSIONS = {'.php', '.php3', '.php4', '.php5', '.py', '.sh', '.pl', '.rb', '.asp', '.aspx', '.jsp'}
    
    SUSPICIOUS_PATTERNS = [
        (r'system\s*\(', 'system() call'),
        (r'exec\s*\(', 'exec() call'),
        (r'base64_decode\s*\(', 'base64_decode() call'),
        (r'curl', 'curl usage'),
        (r'wget', 'wget usage'),
        (r'shell_exec', 'shell_exec() call'),
        (r'passthru', 'passthru() call'),
        (r'subprocess', 'subprocess module'),
        (r'os\.system', 'os.system() call'),
        (r'popen', 'popen() call'),
    ]
    
    def __init__(self, directory, baseline_file='.script_baseline.json'):
        self.directory = directory
        self.baseline_file = baseline_file
        self.baseline = self._load_baseline()
        self.current = {}
        self.alerts = []
    
    def _load_baseline(self):
        """Load baseline."""
        try:
            if os.path.exists(self.baseline_file):
                with open(self.baseline_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}
    
    def _save_baseline(self):
        """Save baseline."""
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
    
    def scan_for_patterns(self, filepath):
        """Scan file for suspicious patterns."""
        patterns_found = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                for pattern, description in self.SUSPICIOUS_PATTERNS:
                    if re.search(pattern, content):
                        patterns_found.append(description)
        except Exception:
            pass
        
        return patterns_found
    
    def scan_directory(self):
        """Scan for executable scripts."""
        for root, dirs, files in os.walk(self.directory):
            for file in files:
                if Path(file).suffix.lower() in self.EXECUTABLE_EXTENSIONS:
                    filepath = os.path.join(root, file)
                    file_hash = self.get_file_hash(filepath)
                    mtime = os.path.getmtime(filepath)
                    
                    if file_hash:
                        self.current[filepath] = {
                            'hash': file_hash,
                            'mtime': mtime,
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        # Check for new files
                        if filepath not in self.baseline:
                            suspicious = self.scan_for_patterns(filepath)
                            
                            self.alerts.append({
                                'type': 'NEW_SCRIPT',
                                'path': filepath,
                                'extension': Path(file).suffix,
                                'suspicious_patterns': suspicious,
                                'risk': 'HIGH' if suspicious else 'MEDIUM',
                                'timestamp': datetime.now().isoformat()
                            })
                        
                        # Check for modifications
                        elif self.baseline[filepath]['hash'] != file_hash:
                            suspicious = self.scan_for_patterns(filepath)
                            
                            self.alerts.append({
                                'type': 'MODIFIED_SCRIPT',
                                'path': filepath,
                                'extension': Path(file).suffix,
                                'suspicious_patterns': suspicious,
                                'risk': 'HIGH' if suspicious else 'MEDIUM',
                                'timestamp': datetime.now().isoformat()
                            })
        
        self._save_baseline()
    
    def report(self):
        """Generate report."""
        high_risk = len([a for a in self.alerts if a.get('risk') == 'HIGH'])
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'directory': self.directory,
            'total_alerts': len(self.alerts),
            'high_risk_count': high_risk,
            'alerts': self.alerts,
            'summary': f"Found {len(self.alerts)} script events ({high_risk} high-risk)"
        }
        return report

def main():
    parser = argparse.ArgumentParser(
        description='Alert on creation and modification of executable scripts.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 php_exe_creation_alerter.py --directory /var/www
  python3 php_exe_creation_alerter.py --directory /app --output alert.json
  python3 php_exe_creation_alerter.py --directory /home --baseline baseline.json
        """)
    
    parser.add_argument('--directory', type=str, required=True, help='Directory to scan')
    parser.add_argument('--output', type=str, help='Output JSON file')
    parser.add_argument('--baseline', type=str, help='Baseline file')
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.directory):
        print(f"[!] Directory not found: {args.directory}")
        return
    
    alerter = PhpExeCreationAlerter(args.directory, args.baseline or '.script_baseline.json')
    
    print(f"[*] Scanning {args.directory} for executable scripts...", flush=True)
    alerter.scan_directory()
    
    report = alerter.report()
    print(json.dumps(report, indent=2))
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")

if __name__ == "__main__":
    main()
