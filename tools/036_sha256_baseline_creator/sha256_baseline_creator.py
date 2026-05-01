#!/usr/bin/env python3
"""
SHA256 Baseline Creator - Creates integrity baseline for directories.
Calculates SHA256 for all files and stores for later comparison.
"""

import sys
import os
import json
import hashlib
import argparse
from datetime import datetime
from pathlib import Path

def calculate_sha256(filepath: str) -> str:
    """Calculate SHA256 hash of a file."""
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except (IOError, OSError):
        return None

def create_baseline(directory: str, output_file: str = "baseline.json") -> dict:
    """Create SHA256 baseline for directory."""
    baseline = {
        'created': datetime.now().isoformat(),
        'directory': os.path.abspath(directory),
        'files': {}
    }
    
    print(f"[*] Creating baseline for {directory}...")
    
    total_files = 0
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                hash_val = calculate_sha256(filepath)
                if hash_val:
                    stat = os.stat(filepath)
                    baseline['files'][filepath] = {
                        'sha256': hash_val,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    }
                    total_files += 1
                    if total_files % 100 == 0:
                        print(f"[*] Processed {total_files} files...")
            except Exception as e:
                pass
    
    # Save baseline
    try:
        with open(output_file, 'w') as f:
            json.dump(baseline, f, indent=2)
        print(f"[+] Baseline created: {output_file}")
        print(f"    Total files: {total_files}")
    except IOError as e:
        print(f"Error writing baseline: {e}", file=sys.stderr)
        return None
    
    return baseline

def update_baseline(directory: str, baseline_file: str) -> dict:
    """Update existing baseline."""
    try:
        with open(baseline_file) as f:
            baseline = json.load(f)
    except (IOError, json.JSONDecodeError):
        return create_baseline(directory, baseline_file)
    
    print(f"[*] Updating baseline...")
    
    updated_files = 0
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                hash_val = calculate_sha256(filepath)
                if hash_val:
                    stat = os.stat(filepath)
                    baseline['files'][filepath] = {
                        'sha256': hash_val,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    }
                    updated_files += 1
            except:
                pass
    
    baseline['updated'] = datetime.now().isoformat()
    with open(baseline_file, 'w') as f:
        json.dump(baseline, f, indent=2)
    
    print(f"[+] Baseline updated: {updated_files} files")
    return baseline

def main():
    parser = argparse.ArgumentParser(
        description="Create SHA256 integrity baseline for a directory",
        epilog="Examples:\n  python3 sha256_baseline_creator.py /var/www\n  python3 sha256_baseline_creator.py /etc --output etc_baseline.json --update"
    )
    parser.add_argument("directory", help="Directory to baseline")
    parser.add_argument("--output", default="baseline.json", help="Output baseline file")
    parser.add_argument("--update", action="store_true", help="Update existing baseline")
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.directory):
        print(f"Error: {args.directory} not found", file=sys.stderr)
        return 1
    
    try:
        if args.update and os.path.exists(args.output):
            update_baseline(args.directory, args.output)
        else:
            create_baseline(args.directory, args.output)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
