#!/usr/bin/env python3
"""
File Owner/Group Tracker - Track ownership changes in file system.

Creates baseline of file owner/group using os.stat().
Saves to JSON for persistent comparison.
Alerts on any ownership changes. Linux/Mac focused.
"""

import argparse
import os
import json
import pwd
import grp
from datetime import datetime
from pathlib import Path

class FileOwnerGroupTracker:
    """Tracks file ownership changes."""
    
    def __init__(self, baseline_file='.owner_baseline.json'):
        self.baseline_file = baseline_file
        self.baseline = self._load_baseline()
        self.current = {}
        self.changes = []
    
    def _load_baseline(self):
        """Load baseline from JSON."""
        try:
            if os.path.exists(self.baseline_file):
                with open(self.baseline_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}
    
    def _save_baseline(self):
        """Save current state as new baseline."""
        try:
            with open(self.baseline_file, 'w') as f:
                json.dump(self.current, f, indent=2)
        except Exception as e:
            print(f"[!] Cannot save baseline: {e}", flush=True)
    
    def get_owner_name(self, uid):
        """Get username from UID."""
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            return str(uid)
    
    def get_group_name(self, gid):
        """Get group name from GID."""
        try:
            return grp.getgrgid(gid).gr_name
        except KeyError:
            return str(gid)
    
    def scan_directory(self, directory):
        """Scan directory and record ownership."""
        for root, dirs, files in os.walk(directory):
            for item in dirs + files:
                filepath = os.path.join(root, item)
                try:
                    stat_info = os.stat(filepath)
                    owner = self.get_owner_name(stat_info.st_uid)
                    group = self.get_group_name(stat_info.st_gid)
                    
                    self.current[filepath] = {
                        'owner': owner,
                        'group': group,
                        'uid': stat_info.st_uid,
                        'gid': stat_info.st_gid,
                        'mode': oct(stat_info.st_mode),
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    # Check for changes
                    if filepath in self.baseline:
                        prev_owner = self.baseline[filepath].get('owner')
                        prev_group = self.baseline[filepath].get('group')
                        
                        if prev_owner != owner or prev_group != group:
                            self.changes.append({
                                'file': filepath,
                                'previous_owner': prev_owner,
                                'current_owner': owner,
                                'previous_group': prev_group,
                                'current_group': group,
                                'timestamp': datetime.now().isoformat()
                            })
                except (OSError, IOError):
                    continue
    
    def report(self):
        """Generate ownership change report."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_files_scanned': len(self.current),
            'ownership_changes': len(self.changes),
            'changes': self.changes,
            'summary': f"Detected {len(self.changes)} ownership changes"
        }
        
        self._save_baseline()
        return report

def main():
    parser = argparse.ArgumentParser(
        description='Track file ownership and group changes.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 file_owner_group_tracker.py --directory /var/www --output changes.json
  python3 file_owner_group_tracker.py --directory /home --baseline my_baseline.json
  python3 file_owner_group_tracker.py --directory /etc --output alert.json --baseline /tmp/baseline.json
        """)
    
    parser.add_argument('--directory', type=str, required=True, help='Directory to scan')
    parser.add_argument('--output', type=str, help='Output JSON file')
    parser.add_argument('--baseline', type=str, help='Baseline file path (default .owner_baseline.json)')
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.directory):
        print(f"[!] Directory not found: {args.directory}")
        return
    
    tracker = FileOwnerGroupTracker(baseline_file=args.baseline or '.owner_baseline.json')
    
    print(f"[*] Scanning {args.directory} for ownership changes...", flush=True)
    tracker.scan_directory(args.directory)
    
    report = tracker.report()
    
    import json
    print(json.dumps(report, indent=2))
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")

if __name__ == "__main__":
    main()
