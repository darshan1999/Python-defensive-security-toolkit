#!/usr/bin/env python3
"""
ASCII String Extractor - Extract printable ASCII strings from binary files.
Accept file path and min length (default 4). Extract sequences of printable ASCII.
Categorize: URLs, IPs, emails, file paths, registry keys, Windows API calls, base64.
Output to console and optional JSON.
"""

import sys
import os
import argparse
import re
import json
from datetime import datetime
from pathlib import Path


class AsciiStringExtractor:
    """Extract and categorize ASCII strings from binary files."""
    
    PATTERNS = {
        'urls': r'https?://[^\s\x00]+',
        'ips': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        'emails': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'file_paths': r'[A-Z]:\\(?:[^\\:\*\?\"\<\>\|]+\\)*[^\\\:\*\?\"\<\>\|]*',
        'registry_keys': r'HKEY_[A-Z_]+\\[^\s\x00]*',
        'windows_apis': r'(CreateProcess|VirtualAlloc|WriteProcessMemory|SetWindowsHookEx|GetModuleHandle|LoadLibrary|CreateRemoteThread|CreateFileA|WriteFile|ReadFile|GetProcAddress)',
        'base64': r'[A-Za-z0-9+/]{32,}={0,2}',
    }
    
    def __init__(self):
        self.timestamp = datetime.now().isoformat()
    
    def extract_ascii_strings(self, file_path, min_length=4):
        """Extract ASCII strings from binary file."""
        strings = []
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            current = []
            for byte in content:
                # Printable ASCII: 0x20-0x7E
                if 0x20 <= byte <= 0x7E:
                    current.append(chr(byte))
                else:
                    if len(current) >= min_length:
                        strings.append(''.join(current))
                    current = []
            
            # Don't forget last string if file doesn't end with null
            if len(current) >= min_length:
                strings.append(''.join(current))
        
        except Exception as e:
            raise Exception(f"Failed to read file: {e}")
        
        return strings
    
    def categorize_strings(self, strings):
        """Categorize extracted strings by pattern."""
        categorized = {
            'urls': [],
            'ips': [],
            'emails': [],
            'file_paths': [],
            'registry_keys': [],
            'windows_apis': [],
            'base64': [],
            'uncategorized': []
        }
        
        for string_sample in strings:
            matched = False
            
            # Check each pattern
            for category, pattern in self.PATTERNS.items():
                try:
                    if re.search(pattern, string_sample):
                        if string_sample not in categorized[category]:
                            categorized[category].append(string_sample)
                        matched = True
                        break
                except Exception:
                    pass
            
            if not matched:
                if string_sample not in categorized['uncategorized']:
                    categorized['uncategorized'].append(string_sample)
        
        return categorized
    
    def process_file(self, file_path, min_length=4):
        """Process file and extract/categorize strings."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        strings = self.extract_ascii_strings(file_path, min_length)
        categorized = self.categorize_strings(strings)
        
        result = {
            'file': file_path,
            'file_size': os.path.getsize(file_path),
            'timestamp': self.timestamp,
            'min_length': min_length,
            'total_strings': len(strings),
            'categories': {k: len(v) for k, v in categorized.items()},
            'strings': categorized
        }
        
        return result
    
    def print_report(self, result):
        """Print formatted extraction report."""
        print("=" * 90)
        print("ASCII STRING EXTRACTION REPORT")
        print("=" * 90)
        print(f"File: {result['file']}")
        print(f"File Size: {result['file_size']} bytes")
        print(f"Timestamp: {result['timestamp']}")
        print(f"Min Length: {result['min_length']} chars")
        print(f"Total Strings: {result['total_strings']}")
        print("")
        
        print("CATEGORY SUMMARY")
        print("-" * 90)
        for category, count in result['categories'].items():
            if count > 0:
                print(f"  {category}: {count}")
        print("")
        
        # Print detailed strings by category
        for category, strings in result['strings'].items():
            if strings:
                print(f"┌─ {category.upper()} ({len(strings)}) ───────────────────────────────────────────────────┐")
                for s in strings[:20]:
                    display = s[:85]
                    if len(s) > 85:
                        display += "..."
                    print(f"│ {display}")
                if len(strings) > 20:
                    print(f"│ ... and {len(strings) - 20} more")
                print("└" + "─" * 87 + "┘")
                print("")
        
        print("=" * 90)


def main():
    parser = argparse.ArgumentParser(
        description='Extract printable ASCII strings from binary files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ascii_string_extractor.py -f malware.bin
  python3 ascii_string_extractor.py -f sample.exe -m 8
  python3 ascii_string_extractor.py -f binary.dat -j strings.json
  python3 ascii_string_extractor.py -f file.bin -m 10 -j output.json
        """)
    
    parser.add_argument('-f', '--file', required=True, help='Binary file to extract strings from')
    parser.add_argument('-m', '--min-length', type=int, default=4, help='Minimum string length (default: 4)')
    parser.add_argument('-j', '--json', help='Output JSON file')
    
    args = parser.parse_args()
    
    try:
        extractor = AsciiStringExtractor()
        result = extractor.process_file(args.file, args.min_length)
        
        extractor.print_report(result)
        
        if args.json:
            # For JSON output, limit uncategorized for file size
            output = result.copy()
            output['strings']['uncategorized'] = result['strings']['uncategorized'][:100]
            
            with open(args.json, 'w') as f:
                json.dump(output, f, indent=2)
            print(f"[+] JSON report written to: {args.json}")
    
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
