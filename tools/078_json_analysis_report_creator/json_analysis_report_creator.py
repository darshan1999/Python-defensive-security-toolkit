#!/usr/bin/env python3
"""
JSON Analysis Report Creator - Create standardized JSON analysis report for suspicious files.
Run: hash calculation, magic byte detection, entropy, string extraction, suspicious pattern check.
Output structured JSON: metadata, hashes, file_type, entropy, string_counts, suspicious_indicators,
risk_score, timestamp.
"""

import sys
import os
import argparse
import json
import hashlib
import re
import math
from datetime import datetime


class JsonAnalysisReportCreator:
    """Create standardized JSON analysis reports."""
    
    MAGIC_SIGNATURES = {
        b'MZ': 'PE_Executable',
        b'\x7fELF': 'ELF_Executable',
        b'PK\x03\x04': 'ZIP_Archive',
        b'%PDF': 'PDF_Document',
    }
    
    SUSPICIOUS_INDICATORS = {
        'c2_beacon': r'beacon|checkin',
        'injection': r'VirtualAlloc|CreateRemoteThread',
        'evasion': r'IsDebuggerPresent|GetModuleHandle',
        'persistence': r'HKEY.*Run|RunOnce',
        'credential': r'password|api_key',
    }
    
    def __init__(self):
        self.timestamp = datetime.now().isoformat()
    
    def calculate_hashes(self, file_path):
        """Calculate file hashes."""
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
            return round(entropy, 4)
        except Exception:
            return 0.0
    
    def extract_strings(self, file_path, min_len=4):
        """Extract ASCII strings."""
        strings = []
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            current = []
            for byte in content:
                if 0x20 <= byte <= 0x7E:
                    current.append(chr(byte))
                else:
                    if len(current) >= min_len:
                        strings.append(''.join(current))
                    current = []
            if len(current) >= min_len:
                strings.append(''.join(current))
        except Exception:
            pass
        
        return strings
    
    def check_suspicious_patterns(self, strings):
        """Check for suspicious patterns."""
        findings = {}
        
        for category, pattern in self.SUSPICIOUS_INDICATORS.items():
            matches = []
            for s in strings:
                if re.search(pattern, s, re.IGNORECASE):
                    if s not in matches:
                        matches.append(s[:100])
            
            if matches:
                findings[category] = {
                    'count': len(matches),
                    'examples': matches[:3]
                }
        
        return findings
    
    def calculate_risk_score(self, file_type, entropy, findings):
        """Calculate overall risk score."""
        score = 0
        
        if 'Executable' in file_type:
            score += 20
        
        if entropy > 7.0:
            score += 20
        
        for indicator in findings:
            if indicator == 'injection':
                score += 25
            elif indicator == 'c2_beacon':
                score += 25
            elif indicator == 'persistence':
                score += 15
            elif indicator == 'evasion':
                score += 15
            elif indicator == 'credential':
                score += 10
        
        return min(score, 100)
    
    def create_report(self, file_path):
        """Create complete JSON report."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        hashes = self.calculate_hashes(file_path)
        file_type, magic_match = self.detect_magic_bytes(file_path)
        entropy = self.calculate_entropy(file_path)
        strings = self.extract_strings(file_path)
        suspicious_indicators = self.check_suspicious_patterns(strings)
        risk_score = self.calculate_risk_score(file_type, entropy, suspicious_indicators)
        
        report = {
            'metadata': {
                'report_timestamp': self.timestamp,
                'tool': 'JsonAnalysisReportCreator',
                'version': '1.0'
            },
            'file_metadata': {
                'path': file_path,
                'name': os.path.basename(file_path),
                'size_bytes': os.path.getsize(file_path),
                'is_accessible': True
            },
            'hashes': hashes,
            'file_type': {
                'detected_format': file_type,
                'magic_byte_match': magic_match
            },
            'entropy': {
                'value': entropy,
                'classification': self._classify_entropy(entropy),
                'is_high_entropy': entropy > 7.0
            },
            'string_analysis': {
                'total_strings_found': len(strings),
                'avg_string_length': round(sum(len(s) for s in strings) / len(strings)) if strings else 0,
                'max_string_length': max(len(s) for s in strings) if strings else 0
            },
            'suspicious_indicators': suspicious_indicators,
            'risk_assessment': {
                'risk_score': risk_score,
                'risk_level': self._get_risk_level(risk_score),
                'indicator_count': len(suspicious_indicators)
            }
        }
        
        return report
    
    def _classify_entropy(self, entropy):
        """Classify entropy."""
        if entropy < 3.0:
            return "plain_text"
        elif entropy < 5.5:
            return "compiled_normal"
        elif entropy < 7.0:
            return "compressed"
        else:
            return "encrypted_packed"
    
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


def main():
    parser = argparse.ArgumentParser(
        description='Create standardized JSON analysis report for files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 json_analysis_report_creator.py -f malware.exe -j report.json
  python3 json_analysis_report_creator.py -f suspicious.bin -o analysis.json
        """)
    
    parser.add_argument('-f', '--file', required=True, help='File to analyze')
    parser.add_argument('-j', '--json', '-o', '--output', dest='output', help='Output JSON file')
    
    args = parser.parse_args()
    
    try:
        creator = JsonAnalysisReportCreator()
        report = creator.create_report(args.file)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[+] Report written to: {args.output}")
        
        # Also print summary
        print("\n" + "=" * 70)
        print("ANALYSIS SUMMARY")
        print("=" * 70)
        print(f"File: {report['file_metadata']['name']}")
        print(f"Risk Score: {report['risk_assessment']['risk_score']}/100 ({report['risk_assessment']['risk_level']})")
        print(f"File Type: {report['file_type']['detected_format']}")
        print(f"Entropy: {report['entropy']['value']} ({report['entropy']['classification']})")
        print(f"Suspicious Indicators: {report['risk_assessment']['indicator_count']}")
        
        if report['suspicious_indicators']:
            print("\nIndicators Found:")
            for indicator, data in report['suspicious_indicators'].items():
                print(f"  - {indicator}: {data['count']} matches")
        
        print("=" * 70)
    
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
