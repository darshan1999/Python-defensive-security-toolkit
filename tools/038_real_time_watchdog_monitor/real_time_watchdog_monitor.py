#!/usr/bin/env python3
"""
Real-time Watchdog Monitor - Detect file system changes without external libraries.

Monitors a directory at regular intervals (default 5s) using polling.
Detects: new files, deleted files, modified files (hash-based integrity).
Prints timestamped alerts per event until Ctrl+C termination.
"""

import argparse
import os
import hashlib
import time
import signal
from datetime import datetime
from pathlib import Path

class RealTimeWatchdog:
    """Monitors directory for file system changes using polling."""
    
    def __init__(self, directory, interval=5, recursive=True):
        self.directory = directory
        self.interval = interval
        self.recursive = recursive
        self.file_state = {}
        self.running = True
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully."""
        print(f"\n[*] Watchdog stopped at {datetime.now().isoformat()}")
        self.running = False
    
    def get_file_hash(self, filepath):
        """Calculate SHA256 hash of file."""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (IOError, OSError):
            return None
    
    def scan_directory(self):
        """Scan directory and return current file state."""
        current_state = {}
        
        if self.recursive:
            pattern = self.directory + '/**/*'
            for filepath in Path(self.directory).rglob('*'):
                if filepath.is_file():
                    current_state[str(filepath)] = self.get_file_hash(str(filepath))
        else:
            for entry in os.listdir(self.directory):
                filepath = os.path.join(self.directory, entry)
                if os.path.isfile(filepath):
                    current_state[filepath] = self.get_file_hash(filepath)
        
        return current_state
    
    def detect_changes(self, new_state):
        """Detect and report changes from previous state."""
        alerts = []
        
        # Check for new files
        for filepath in new_state:
            if filepath not in self.file_state:
                alerts.append({
                    'type': 'NEW_FILE',
                    'path': filepath,
                    'timestamp': datetime.now().isoformat()
                })
        
        # Check for deleted files
        for filepath in self.file_state:
            if filepath not in new_state:
                alerts.append({
                    'type': 'DELETED_FILE',
                    'path': filepath,
                    'timestamp': datetime.now().isoformat()
                })
        
        # Check for modified files
        for filepath in self.file_state:
            if filepath in new_state:
                if self.file_state[filepath] != new_state[filepath]:
                    alerts.append({
                        'type': 'MODIFIED_FILE',
                        'path': filepath,
                        'timestamp': datetime.now().isoformat()
                    })
        
        return alerts
    
    def monitor(self):
        """Start monitoring loop."""
        print(f"[*] Watchdog started on {self.directory}", flush=True)
        print(f"[*] Check interval: {self.interval}s", flush=True)
        print(f"[*] Recursive: {self.recursive}", flush=True)
        print(f"[*] Press Ctrl+C to stop\n", flush=True)
        
        # Initial scan
        self.file_state = self.scan_directory()
        print(f"[*] Initial baseline: {len(self.file_state)} files", flush=True)
        
        while self.running:
            try:
                time.sleep(self.interval)
                new_state = self.scan_directory()
                alerts = self.detect_changes(new_state)
                
                for alert in alerts:
                    print(f"[ALERT] {alert['timestamp']} - {alert['type']}: {alert['path']}", flush=True)
                
                self.file_state = new_state
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] Error during monitoring: {e}", flush=True)

def main():
    parser = argparse.ArgumentParser(
        description='Real-time file system change detection using polling.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 real_time_watchdog_monitor.py --directory /var/www
  python3 real_time_watchdog_monitor.py --directory /app --interval 3 --recursive
  python3 real_time_watchdog_monitor.py --directory /home/user --interval 10 --no-recursive
        """)
    
    parser.add_argument('--directory', type=str, required=True, help='Directory to monitor')
    parser.add_argument('--interval', type=int, default=5, help='Check interval in seconds (default 5)')
    parser.add_argument('--recursive', action='store_true', default=True, help='Monitor subdirectories')
    parser.add_argument('--no-recursive', dest='recursive', action='store_false', help='Do not monitor subdirectories')
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.directory):
        print(f"[!] Directory not found: {args.directory}")
        return
    
    watchdog = RealTimeWatchdog(args.directory, interval=args.interval, recursive=args.recursive)
    watchdog.monitor()

if __name__ == "__main__":
    main()
