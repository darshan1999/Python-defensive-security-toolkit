#!/usr/bin/env python3
"""
Scheduled File Monitor - Periodic integrity checks using sched module.

Monitors directory at specified interval (minutes). Logs all changes with timestamp.
Graceful shutdown on SIGINT. Creates rotating log of all modifications.
"""

import argparse
import os
import sched
import signal
import hashlib
import json
from datetime import datetime
from pathlib import Path

class ScheduledFileMonitor:
    """Periodic file integrity monitoring using sched."""
    
    def __init__(self, directory, check_interval_minutes=5, log_file='file_monitor.log'):
        self.directory = directory
        self.check_interval = check_interval_minutes * 60
        self.log_file = log_file
        self.scheduler = sched.scheduler()
        self.file_hashes = {}
        self.running = True
        
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, sig, frame):
        """Handle graceful shutdown."""
        print(f"\n[*] Monitor stopped at {datetime.now().isoformat()}", flush=True)
        self.running = False
        self.scheduler.empty()
    
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
    
    def scan_files(self):
        """Scan directory for file changes."""
        current_hashes = {}
        changes = []
        
        for root, dirs, files in os.walk(self.directory):
            for file in files:
                filepath = os.path.join(root, file)
                file_hash = self.get_file_hash(filepath)
                
                if file_hash:
                    current_hashes[filepath] = file_hash
                    
                    if filepath not in self.file_hashes:
                        changes.append({
                            'type': 'NEW',
                            'path': filepath,
                            'timestamp': datetime.now().isoformat()
                        })
                    elif self.file_hashes[filepath] != file_hash:
                        changes.append({
                            'type': 'MODIFIED',
                            'path': filepath,
                            'timestamp': datetime.now().isoformat()
                        })
        
        # Detect deletions
        for filepath in self.file_hashes:
            if filepath not in current_hashes:
                changes.append({
                    'type': 'DELETED',
                    'path': filepath,
                    'timestamp': datetime.now().isoformat()
                })
        
        self.file_hashes = current_hashes
        return changes
    
    def log_changes(self, changes):
        """Log changes to file."""
        if changes:
            try:
                with open(self.log_file, 'a') as f:
                    for change in changes:
                        f.write(json.dumps(change) + '\n')
                        print(f"[{change['timestamp']}] {change['type']}: {change['path']}", flush=True)
            except IOError as e:
                print(f"[!] Cannot write to log: {e}", flush=True)
    
    def check(self):
        """Perform scheduled check."""
        try:
            changes = self.scan_files()
            self.log_changes(changes)
            
            if self.running:
                self.scheduler.enter(self.check_interval, 1, self.check)
        except Exception as e:
            print(f"[!] Error during check: {e}", flush=True)
    
    def monitor(self):
        """Start monitoring."""
        print(f"[*] Started monitoring {self.directory}", flush=True)
        print(f"[*] Check interval: {self.check_interval}s", flush=True)
        print(f"[*] Log file: {self.log_file}", flush=True)
        print(f"[*] Press Ctrl+C to stop\n", flush=True)
        
        # Initial scan
        self.scan_files()
        print(f"[*] Baseline established: {len(self.file_hashes)} files", flush=True)
        
        # Schedule first check
        self.scheduler.enter(self.check_interval, 1, self.check)
        
        try:
            self.scheduler.run()
        except KeyboardInterrupt:
            pass

def main():
    parser = argparse.ArgumentParser(
        description='Scheduled file integrity monitoring.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scheduled_file_monitor.py --directory /var/www
  python3 scheduled_file_monitor.py --directory /app --interval 10 --log app_monitor.log
  python3 scheduled_file_monitor.py --directory /etc --interval 30 --log /var/log/file_monitor.log
        """)
    
    parser.add_argument('--directory', type=str, required=True, help='Directory to monitor')
    parser.add_argument('--interval', type=int, default=5, help='Check interval in minutes (default 5)')
    parser.add_argument('--log', type=str, default='file_monitor.log', help='Log file path')
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.directory):
        print(f"[!] Directory not found: {args.directory}")
        return
    
    monitor = ScheduledFileMonitor(args.directory, args.interval, args.log)
    monitor.monitor()

if __name__ == "__main__":
    main()
