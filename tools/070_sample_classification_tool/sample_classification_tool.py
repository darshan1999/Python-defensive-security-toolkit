#!/usr/bin/env python3
"""
Sample Classification Tool - Classify files based on static analysis.
Accept file/directory. For each: detect type by magic bytes, calculate entropy,
extract strings and categorize (network: IPs/URLs, persistence: registry/startup,
evasion: anti-debug, credential: passwords). Output classification with evidence.
"""

import sys
import os
import argparse
import json
import re
import math
from pathlib import Path
from datetime import datetime


class SampleClassificationTool:
    """Classify files based on static analysis indicators."""
    
    MAGIC_BYTES = {
        b'MZ': 'PE_Executable',
        b'\x7fELF': 'ELF_Executable',
        b'PK\x03\x04': 'ZIP_Archive',
        b'%PDF': 'PDF_Document',
        b'\x1f\x8b': 'GZIP_Compressed',
        b'BM': 'Bitmap_Image',
    }
    
    INDICATORS = {
        'network': [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP
            r'https?://[^\s]+',  # URL
            r'ftp://[^\s]+',  # FTP
        ],
        'persistence': [
            'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            'RunOnce', 'Run', 'Startup',
            'startupfolder', 'startup',
        ],
        'evasion': [
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'ntdll',
            'VirtualProtect', 'SetWindowsHookEx', 'GetModuleHandle',
            'anti', 'debug', 'debugger', 'antivirus', 'sandbox',
        ],
        'credential': [
            'password', 'passwd', 'pwd', 'credential', 'token',
            'api_key', 'apikey', 'secret', 'private_key',
            'username', 'user_name', 'account',
        ],
    }
    
    def __init__(self):
        self.timestamp = datetime.now().isoformat()
    
    def detect_file_type_by_magic(self, file_path):
        """Detect file type by magic bytes."""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
            
            for sig, fmt in self.MAGIC_BYTES.items():
                if magic.startswith(sig):
                    return fmt, True
            
            return "Unknown", False
        except Exception:
            return "Unknown", False
    
    def calculate_entropy(self, file_path):
        """Calculate Shannon entropy."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not data:
                return 0.0
            
            entropy = 0.0
            for byte_val in range(256):
                freq = data.count(bytes([byte_val]))
                if freq:
                    p = freq / len(data)
                    entropy -= p * (math.log(p) / math.log(2))
            
            return round(entropy, 2)
        except Exception:
            return 0.0
    
    def classify_entropy(self, entropy):
        """Classify entropy value."""
        if entropy < 3.0:
            return "plain_text"
        elif entropy < 5.5:
            return "compiled_normal"
        elif entropy < 7.0:
            return "compressed"
        else:
            return "encrypted_packed"
    
    def extract_strings(self, file_path, min_len=4):
        """Extract printable ASCII strings."""
        strings = []
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            current = []
            for byte in content:
                if 32 <= byte <= 126:
                    current.append(chr(byte))
                else:
                    if len(current) >= min_len:
                        strings.append(''.join(current))
                    current = []
            
            if len(current) >= min_len:
                strings.append(''.join(current))
        
        except Exception:
            pass
        
        return strings[:200]
    
    def categorize_strings(self, strings):
        """Categorize extracted strings."""
        categories = {
            'network': [],
            'persistence': [],
            'evasion': [],
            'credential': []
        }
        
        for category, patterns in self.INDICATORS.items():
            for pattern in patterns:
                for string_sample in strings:
                    if re.search(pattern, string_sample, re.IGNORECASE):
                        if string_sample not in categories[category]:
                            categories[category].append(string_sample)
        
        return categories
    
    def classify_file(self, file_path):
        """Classify single file."""
        try:
            file_type, magic_match = self.detect_file_type_by_magic(file_path)
            entropy = self.calculate_entropy(file_path)
            entropy_class = self.classify_entropy(entropy)
            
            strings = self.extract_strings(file_path)
            string_categories = self.categorize_strings(strings)
            
            risk_score = self._calculate_risk_score(
                file_type, entropy, entropy_class, string_categories
            )
            
            return {
                'file': file_path,
                'size': os.path.getsize(file_path),
                'file_type': file_type,
                'magic_match': magic_match,
                'entropy': entropy,
                'entropy_class': entropy_class,
                'string_count': len(strings),
                'string_categories': {k: len(v) for k, v in string_categories.items()},
                'indicators_found': string_categories,
                'risk_score': risk_score,
                'risk_level': self._get_risk_level(risk_score)
            }
        except Exception as e:
            return {
                'file': file_path,
                'error': str(e),
                'risk_level': 'unknown'
            }
    
    def _calculate_risk_score(self, file_type, entropy, entropy_class, categories):
        """Calculate risk score."""
        score = 0
        
        if 'Executable' in file_type:
            score += 30
        
        if entropy_class in ['encrypted_packed', 'compressed']:
            score += 20
        
        for category, items in categories.items():
            if items:
                if category == 'evasion':
                    score += 25
                elif category == 'credential':
                    score += 20
                elif category == 'persistence':
                    score += 15
                elif category == 'network':
                    score += 10
        
        return min(score, 100)
    
    def _get_risk_level(self, score):
        """Get risk level from score."""
        if score >= 70:
            return "High"
        elif score >= 40:
            return "Medium"
        elif score >= 20:
            return "Low"
        else:
            return "Minimal"
    
    def process_files(self, path):
        """Process file or directory."""
        results = []
        
        if os.path.isfile(path):
            results.append(self.classify_file(path))
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        results.append(self.classify_file(file_path))
                    except Exception:
                        pass
        else:
            raise FileNotFoundError(f"Path not found: {path}")
        
        return results
    
    def print_report(self, results):
        """Print formatted classification report."""
        print("=" * 90)
        print("FILE CLASSIFICATION REPORT")
        print("=" * 90)
        print(f"Timestamp: {self.timestamp}")
        print(f"Total Files: {len(results)}")
        print("")
        
        for result in results:
            if 'error' in result:
                print(f"[-] {result['file']}: {result['error']}")
                continue
            
            print(f"File: {result['file']}")
            print(f"  Size: {result['size']} bytes")
            print(f"  Type: {result['file_type']} (magic match: {result['magic_match']})")
            print(f"  Entropy: {result['entropy']} ({result['entropy_class']})")
            print(f"  Strings: {result['string_count']}")
            
            if any(result['string_categories'].values()):
                print(f"  Indicators:")
                for cat, count in result['string_categories'].items():
                    if count > 0:
                        print(f"    - {cat}: {count}")
            
            print(f"  Risk Score: {result['risk_score']}/100 ({result['risk_level']})")
            print("")


def main():
    parser = argparse.ArgumentParser(
        description='Classify files based on static analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 sample_classification_tool.py -f suspicious_file.exe
  python3 sample_classification_tool.py -d /path/to/samples -j classification.json
        """)
    
    parser.add_argument('-f', '--file', help='Single file to classify')
    parser.add_argument('-d', '--directory', help='Directory to scan recursively')
    parser.add_argument('-j', '--json', help='Output JSON report')
    
    args = parser.parse_args()
    
    if not args.file and not args.directory:
        parser.print_help()
        sys.exit(1)
    
    try:
        classifier = SampleClassificationTool()
        
        if args.file:
            path = args.file
        else:
            path = args.directory
        
        results = classifier.process_files(path)
        classifier.print_report(results)
        
        if args.json:
            with open(args.json, 'w') as f:
                json.dump({
                    'timestamp': classifier.timestamp,
                    'results': results
                }, f, indent=2)
            print(f"[+] JSON report written to: {args.json}")
    
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
