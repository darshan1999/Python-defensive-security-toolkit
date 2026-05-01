#!/usr/bin/env python3
"""
Batch File Hasher - Calculates MD5, SHA1, SHA256 for all files in a directory.
Saves results to CSV with file metadata for forensic analysis.
"""

import sys
import os
import csv
import hashlib
import argparse
import time
from pathlib import Path
from datetime import datetime

def calculate_hashes(filepath: str) -> dict:
    """Calculate MD5, SHA1, SHA256 for a file."""
    try:
        data = open(filepath, 'rb').read()
        stat = os.stat(filepath)
        return {
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(),
            'file_size': len(data),
            'last_modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
        }
    except Exception as e:
        return None

def hash_directory(directory: str, exclude_patterns: list = None) -> list:
    """Hash all files in directory."""
    if exclude_patterns is None:
        exclude_patterns = ['.git', 'node_modules', '__pycache__', '.env']
    
    results = []
    total_files = 0
    
    print(f"[*] Hashing files in {directory}...")
    
    for root, dirs, files in os.walk(directory):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in exclude_patterns]
        
        for file in files:
            filepath = os.path.join(root, file)
            
            # Skip excluded patterns
            if any(pattern in filepath for pattern in exclude_patterns):
                continue
            
            try:
                hashes = calculate_hashes(filepath)
                if hashes:
                    results.append({
                        'filepath': filepath,
                        'md5': hashes['md5'],
                        'sha1': hashes['sha1'],
                        'sha256': hashes['sha256'],
                        'file_size': hashes['file_size'],
                        'last_modified': hashes['last_modified']
                    })
                    total_files += 1
                    
                    if total_files % 50 == 0:
                        print(f"[*] Processed {total_files} files...")
            except Exception as e:
                pass
    
    return results

def main():
    parser = argparse.ArgumentParser(
        description="Batch calculate hashes for all files in a directory",
        epilog="Example: python3 batch_file_hasher.py /var/www --output web_hashes.csv --exclude .git node_modules"
    )
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--output", default="hashes.csv", help="Output CSV file")
    parser.add_argument("--exclude", nargs="+", help="Directories/patterns to exclude")
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.directory):
        print(f"Error: {args.directory} not found", file=sys.stderr)
        return 1
    
    try:
        start_time = time.time()
        
        exclude_patterns = args.exclude or ['.git', 'node_modules', '__pycache__']
        results = hash_directory(args.directory, exclude_patterns)
        
        elapsed = time.time() - start_time
        
        # Write to CSV
        if results:
            with open(args.output, 'w', newline='') as f:
                fieldnames = ['filepath', 'md5', 'sha1', 'sha256', 'file_size', 'last_modified']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
        
        print(f"\n[+] Batch Hashing Complete")
        print(f"    Total files: {len(results)}")
        print(f"    Time taken: {elapsed:.2f} seconds")
        print(f"    Output: {args.output}")
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
