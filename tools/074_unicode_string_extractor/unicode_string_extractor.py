#!/usr/bin/env python3
"""
Unicode String Extractor - Extract Unicode (UTF-16LE) strings from binary files.
Search for UTF-16LE encoded strings (alternating null bytes). Extract and decode.
Filter printable. Categorize like ASCII extractor. Combine and deduplicate results.
Modern malware uses Unicode strings to evade ASCII extraction.
"""

import sys
import os
import argparse
import re
import json
from datetime import datetime


class UnicodeStringExtractor:
    """Extract and categorize Unicode (UTF-16LE) strings from binary files."""
    
    PATTERNS = {
        'urls': r'https?://[^\s\x00]+',
        'ips': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        'emails': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'file_paths': r'[A-Z]:\\(?:[^\\:\*\?\"\<\>\|]+\\)*[^\\\:\*\?\"\<\>\|]*',
        'registry_keys': r'HKEY_[A-Z_]+\\[^\s\x00]*',
        'windows_apis': r'(CreateProcess|VirtualAlloc|WriteProcessMemory|SetWindowsHookEx)',
    }
    
    def __init__(self):
        self.timestamp = datetime.now().isoformat()
    
    def extract_utf16le_strings(self, file_path, min_length=4):
        """Extract UTF-16LE encoded strings (alternating null bytes)."""
        strings = []
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            i = 0
            while i < len(content) - 1:
                # Look for UTF-16LE pattern: byte, 0x00, byte, 0x00...
                if i + 1 < len(content) and content[i + 1] == 0x00:
                    current = []
                    j = i
                    
                    while j + 1 < len(content):
                        char_byte = content[j]
                        null_byte = content[j + 1]
                        
                        # Valid UTF-16LE continuation
                        if null_byte == 0x00 and 0x20 <= char_byte <= 0x7E:
                            current.append(chr(char_byte))
                            j += 2
                        else:
                            break
                    
                    if len(current) >= min_length:
                        decoded = ''.join(current)
                        strings.append(decoded)
                    
                    i = j if j > i + 2 else i + 2
                else:
                    i += 1
        
        except Exception as e:
            raise Exception(f"Failed to read file: {e}")
        
        return strings
    
    def extract_ascii_strings(self, file_path, min_length=4):
        """Extract regular ASCII strings."""
        strings = []
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            current = []
            for byte in content:
                if 0x20 <= byte <= 0x7E:
                    current.append(chr(byte))
                else:
                    if len(current) >= min_length:
                        strings.append(''.join(current))
                    current = []
            
            if len(current) >= min_length:
                strings.append(''.join(current))
        
        except Exception:
            pass
        
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
            'other': []
        }
        
        for string_sample in strings:
            matched = False
            
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
                if string_sample not in categorized['other']:
                    categorized['other'].append(string_sample)
        
        return categorized
    
    def process_file(self, file_path, min_length=4):
        """Process file and extract both ASCII and Unicode strings."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        ascii_strings = self.extract_ascii_strings(file_path, min_length)
        unicode_strings = self.extract_utf16le_strings(file_path, min_length)
        
        # Combine and deduplicate
        all_strings = list(set(ascii_strings + unicode_strings))
        
        categorized = self.categorize_strings(all_strings)
        
        result = {
            'file': file_path,
            'file_size': os.path.getsize(file_path),
            'timestamp': self.timestamp,
            'min_length': min_length,
            'ascii_strings': len(ascii_strings),
            'unicode_strings': len(unicode_strings),
            'total_strings': len(all_strings),
            'categories': {k: len(v) for k, v in categorized.items()},
            'strings': categorized
        }
        
        return result
    
    def print_report(self, result):
        """Print formatted extraction report."""
        print("=" * 90)
        print("UNICODE + ASCII STRING EXTRACTION REPORT")
        print("=" * 90)
        print(f"File: {result['file']}")
        print(f"File Size: {result['file_size']} bytes")
        print(f"Timestamp: {result['timestamp']}")
        print(f"Min Length: {result['min_length']} chars")
        print("")
        
        print("EXTRACTION SUMMARY")
        print("-" * 90)
        print(f"  ASCII Strings: {result['ascii_strings']}")
        print(f"  Unicode (UTF-16LE) Strings: {result['unicode_strings']}")
        print(f"  Total Unique Strings: {result['total_strings']}")
        print("")
        
        print("CATEGORY SUMMARY")
        print("-" * 90)
        for category, count in result['categories'].items():
            if count > 0:
                print(f"  {category}: {count}")
        print("")
        
        # Print top strings by category
        for category, strings in result['strings'].items():
            if strings:
                count = min(15, len(strings))
                print(f"┌─ {category.upper()} (showing {count}/{len(strings)}) ────────────────────────────┐")
                for s in strings[:15]:
                    display = s[:80]
                    if len(s) > 80:
                        display += "..."
                    print(f"│ {display}")
                if len(strings) > 15:
                    print(f"│ ... and {len(strings) - 15} more")
                print("└" + "─" * 85 + "┘")
                print("")
        
        print("=" * 90)


def main():
    parser = argparse.ArgumentParser(
        description='Extract Unicode (UTF-16LE) and ASCII strings from binary files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 unicode_string_extractor.py -f malware.bin
  python3 unicode_string_extractor.py -f sample.exe -m 8
  python3 unicode_string_extractor.py -f binary.dat -j strings.json
        """)
    
    parser.add_argument('-f', '--file', required=True, help='Binary file to extract strings from')
    parser.add_argument('-m', '--min-length', type=int, default=4, help='Minimum string length (default: 4)')
    parser.add_argument('-j', '--json', help='Output JSON file')
    
    args = parser.parse_args()
    
    try:
        extractor = UnicodeStringExtractor()
        result = extractor.process_file(args.file, args.min_length)
        
        extractor.print_report(result)
        
        if args.json:
            # Limit output for file size
            output = result.copy()
            for category in output['strings']:
                output['strings'][category] = output['strings'][category][:100]
            
            with open(args.json, 'w') as f:
                json.dump(output, f, indent=2)
            print(f"[+] JSON report written to: {args.json}")
    
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
