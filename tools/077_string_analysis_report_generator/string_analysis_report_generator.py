#!/usr/bin/env python3
"""
String Analysis Report Generator - Generate complete string analysis report.
Combine ASCII and Unicode extraction, entropy calculation, suspicious string ID,
magic byte detection. Output structured report: File Info, Strings Summary,
Suspicious Findings, Risk Score (0-100).
"""

import sys
import os
import argparse
import json
import re
import math
from pathlib import Path
from datetime import datetime


class StringAnalysisReportGenerator:
    """Generate comprehensive string analysis reports."""
    
    SUSPICIOUS_PATTERNS = {
        'c2': r'(beacon|checkin|callback|command.server)',
        'injection': r'(VirtualAlloc|CreateRemoteThread|WriteProcessMemory)',
        'evasion': r'(IsDebuggerPresent|GetModuleHandle)',
        'credential': r'(password|passwd|api_key|token)',
        'persistence': r'(HKEY.*Run|RunOnce|Startup)',
    }
    
    MAGIC_SIGNATURES = {
        b'MZ': 'PE_Executable',
        b'\x7fELF': 'ELF_Executable',
        b'PK\x03\x04': 'ZIP_Archive',
        b'%PDF': 'PDF_Document',
    }
    
    def __init__(self):
        self.timestamp = datetime.now().isoformat()
    
    def detect_magic_bytes(self, file_path):
        """Detect file type by magic bytes."""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
            
            for sig, fmt in self.MAGIC_SIGNATURES.items():
                if magic.startswith(sig):
                    return fmt, True
            return "Unknown", False
        except Exception:
            return "Unknown", False
    
    def calculate_hashes(self, file_path):
        """Calculate MD5, SHA1, SHA256."""
        import hashlib
        hashes = {}
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                hashes['md5'] = hashlib.md5(content).hexdigest()
                hashes['sha1'] = hashlib.sha1(content).hexdigest()
                hashes['sha256'] = hashlib.sha256(content).hexdigest()
        except Exception:
            pass
        return hashes
    
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
    
    def extract_strings(self, file_path, min_len=4):
        """Extract ASCII and Unicode strings."""
        ascii_strings = []
        unicode_strings = []
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # ASCII
            current = []
            for byte in content:
                if 0x20 <= byte <= 0x7E:
                    current.append(chr(byte))
                else:
                    if len(current) >= min_len:
                        ascii_strings.append(''.join(current))
                    current = []
            if len(current) >= min_len:
                ascii_strings.append(''.join(current))
            
            # Unicode (UTF-16LE)
            for i in range(len(content) - 1):
                if content[i + 1] == 0x00 and 0x20 <= content[i] <= 0x7E:
                    current = []
                    j = i
                    while j + 1 < len(content) and content[j + 1] == 0x00 and 0x20 <= content[j] <= 0x7E:
                        current.append(chr(content[j]))
                        j += 2
                    if len(current) >= min_len:
                        unicode_strings.append(''.join(current))
        
        except Exception:
            pass
        
        return ascii_strings, unicode_strings
    
    def identify_suspicious_indicators(self, strings):
        """Identify suspicious patterns in strings."""
        indicators = {}
        
        for category, pattern in self.SUSPICIOUS_PATTERNS.items():
            matches = []
            for s in strings:
                if re.search(pattern, s, re.IGNORECASE):
                    if s not in matches:
                        matches.append(s)
            if matches:
                indicators[category] = matches[:5]
        
        return indicators
    
    def calculate_risk_score(self, entropy, file_type, indicators):
        """Calculate overall risk score."""
        score = 0
        
        if 'Executable' in file_type:
            score += 20
        
        if entropy > 7.0:
            score += 20
        
        for category in indicators:
            if category == 'c2':
                score += 25
            elif category == 'injection':
                score += 20
            elif category == 'evasion':
                score += 15
            elif category == 'credential':
                score += 10
            elif category == 'persistence':
                score += 15
        
        return min(score, 100)
    
    def generate_report(self, file_path):
        """Generate complete analysis report."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        file_type, magic_match = self.detect_magic_bytes(file_path)
        hashes = self.calculate_hashes(file_path)
        entropy = self.calculate_entropy(file_path)
        ascii_strings, unicode_strings = self.extract_strings(file_path)
        all_strings = list(set(ascii_strings + unicode_strings))
        
        indicators = self.identify_suspicious_indicators(all_strings)
        risk_score = self.calculate_risk_score(entropy, file_type, indicators)
        
        report = {
            'timestamp': self.timestamp,
            'file_info': {
                'path': file_path,
                'name': os.path.basename(file_path),
                'size': os.path.getsize(file_path)
            },
            'hashes': hashes,
            'file_type': {
                'detected': file_type,
                'magic_matched': magic_match
            },
            'entropy': {
                'value': entropy,
                'classification': self._classify_entropy(entropy)
            },
            'strings_summary': {
                'ascii_count': len(ascii_strings),
                'unicode_count': len(unicode_strings),
                'unique_count': len(all_strings)
            },
            'suspicious_findings': indicators,
            'risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score)
        }
        
        return report
    
    def _classify_entropy(self, entropy):
        """Classify entropy."""
        if entropy < 3.0:
            return "Plain Text"
        elif entropy < 5.5:
            return "Compiled/Normal"
        elif entropy < 7.0:
            return "Compressed"
        else:
            return "Encrypted/Packed"
    
    def _get_risk_level(self, score):
        """Get risk level."""
        if score >= 70:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        else:
            return "LOW"
    
    def print_report(self, report):
        """Print formatted report."""
        print("=" * 90)
        print("COMPREHENSIVE STRING ANALYSIS REPORT")
        print("=" * 90)
        print(f"Timestamp: {report['timestamp']}")
        print("")
        
        print("FILE INFORMATION")
        print("-" * 90)
        print(f"  Path: {report['file_info']['path']}")
        print(f"  Name: {report['file_info']['name']}")
        print(f"  Size: {report['file_info']['size']} bytes")
        print("")
        
        print("HASHES")
        print("-" * 90)
        for hash_type, hash_val in report['hashes'].items():
            print(f"  {hash_type.upper()}: {hash_val}")
        print("")
        
        print("FILE TYPE & ENTROPY")
        print("-" * 90)
        print(f"  Detected: {report['file_type']['detected']}")
        print(f"  Entropy: {report['entropy']['value']} ({report['entropy']['classification']})")
        print("")
        
        print("STRING ANALYSIS")
        print("-" * 90)
        print(f"  ASCII Strings: {report['strings_summary']['ascii_count']}")
        print(f"  Unicode Strings: {report['strings_summary']['unicode_count']}")
        print(f"  Unique Strings: {report['strings_summary']['unique_count']}")
        print("")
        
        if report['suspicious_findings']:
            print("SUSPICIOUS INDICATORS")
            print("-" * 90)
            for category, findings in report['suspicious_findings'].items():
                print(f"  {category.upper()}:")
                for finding in findings[:3]:
                    print(f"    • {finding[:70]}")
        
        print("")
        print("RISK ASSESSMENT")
        print("-" * 90)
        print(f"  Risk Score: {report['risk_score']}/100")
        print(f"  Risk Level: {report['risk_level']}")
        print("=" * 90)


def main():
    parser = argparse.ArgumentParser(
        description='Generate comprehensive string analysis report',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 string_analysis_report_generator.py -f malware.exe
  python3 string_analysis_report_generator.py -f sample.bin -j report.json
        """)
    
    parser.add_argument('-f', '--file', required=True, help='File to analyze')
    parser.add_argument('-j', '--json', help='Output JSON file')
    
    args = parser.parse_args()
    
    try:
        generator = StringAnalysisReportGenerator()
        report = generator.generate_report(args.file)
        
        generator.print_report(report)
        
        if args.json:
            with open(args.json, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[+] JSON report written to: {args.json}")
    
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
