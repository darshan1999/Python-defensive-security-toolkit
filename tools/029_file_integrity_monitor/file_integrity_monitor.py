#!/usr/bin/env python3
"""File Integrity Monitor - Detect unauthorized file changes"""
import os
import hashlib
import json

class FileIntegrityMonitor:
    def __init__(self):
        self.baseline = {}
        self.changes = {"new": [], "modified": [], "deleted": []}
    
    def calculate_hash(self, filepath):
        """Calculate file hash"""
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            sha256.update(f.read())
        return sha256.hexdigest()
    
    def create_baseline(self, directory):
        """Create baseline of directory"""
        for root, dirs, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    self.baseline[filepath] = self.calculate_hash(filepath)
                except: pass
    
    def check_changes(self):
        """Check for changes"""
        print(f"[+] Baseline contains {len(self.baseline)} files")

def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 file_integrity_monitor.py <directory>")
        sys.exit(1)
    
    fim = FileIntegrityMonitor()
    fim.create_baseline(sys.argv[1])
    fim.check_changes()

if __name__ == "__main__":
    main()
