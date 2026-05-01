#!/usr/bin/env python3
"""
Unknown Attachment Triager - Triage unknown email attachments.
Run: magic byte check (is format correct?), entropy check (encrypted/packed?),
extension mismatch detection, hash lookup against local known-bad list,
string scan for URLs/IPs/suspicious APIs. Generate verdict: CLEAN/SUSPICIOUS/MALICIOUS
with confidence score and evidence list. Output JSON.
"""

import sys
import os
import argparse
import json
import hashlib
import re
import math
from datetime import datetime
from pathlib import Path


class UnknownAttachmentTriager:
    """Triage unknown email attachments."""
    
    KNOWN_BAD_HASHES = set([
        "5d41402abc4b2a76b9719d911017c592",  # Example known-bad hash
    ])
    
    MAGIC_SIGNATURES = {
        b'MZ': ('PE_Executable', ['.exe', '.dll', '.scr']),
        b'\x7fELF': ('ELF_Executable', ['.elf']),
        b'PK\x03\x04': ('ZIP_Archive', ['.zip', '.docx']),
    }
    
    SUSPICIOUS_INDICATORS = {
        'urls': r'https?://[^\s]+',
        'ips': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        'powershell': r'powershell',
        'cmd_execution': r'cmd\.exe|cmd /c',
        'api_calls': r'(CreateProcess|VirtualAlloc|WriteProcessMemory)',
    }
    
    def __init__(self, known_bad_file=None):
        self.timestamp = datetime.now().isoformat()
        if known_bad_file and os.path.exists(known_bad_file):
            self._load_known_bad(known_bad_file)
    
    def _load_known_bad(self, file_path):
        """Load known-bad hash list."""
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    h = line.strip()
                    if h:
                        self.KNOWN_BAD_HASHES.add(h.lower())
        except Exception:
            pass
    
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
    
    def check_magic_bytes(self, file_path):
        """Check file magic bytes."""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
            
            ext = Path(file_path).suffix.lower()
            
            for sig, (fmt, expected_exts) in self.MAGIC_SIGNATURES.items():
                if magic.startswith(sig):
                    mismatch = ext not in expected_exts and ext != ''
                    return {
                        'format': fmt,
                        'magic_match': True,
                        'extension': ext,
                        'mismatch': mismatch
                    }
            
            return {
                'format': 'Unknown',
                'magic_match': False,
                'extension': ext,
                'mismatch': False
            }
        except Exception:
            return None
    
    def check_entropy(self, file_path):
        """Check file entropy."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not data:
                return 0.0, False
            
            entropy = 0.0
            for byte_val in range(256):
                freq = data.count(bytes([byte_val]))
                if freq:
                    p = freq / len(data)
                    entropy -= p * (math.log(p) / math.log(2))
            
            is_suspicious = entropy > 7.0
            return round(entropy, 2), is_suspicious
        except Exception:
            return 0.0, False
    
    def hash_lookup(self, hashes):
        """Check if hash is in known-bad list."""
        for hash_type, hash_val in hashes.items():
            if hash_val.lower() in self.KNOWN_BAD_HASHES:
                return True, hash_type
        return False, None
    
    def scan_suspicious_content(self, file_path):
        """Scan file for suspicious content."""
        indicators = {}
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Extract strings
            current = []
            strings = []
            for byte in content:
                if 0x20 <= byte <= 0x7E:
                    current.append(chr(byte))
                else:
                    if len(current) >= 4:
                        strings.append(''.join(current))
                    current = []
            if len(current) >= 4:
                strings.append(''.join(current))
            
            # Check indicators
            for category, pattern in self.SUSPICIOUS_INDICATORS.items():
                matches = []
                for s in strings:
                    if re.search(pattern, s, re.IGNORECASE):
                        if s not in matches:
                            matches.append(s[:70])
                
                if matches:
                    indicators[category] = matches[:3]
        
        except Exception:
            pass
        
        return indicators
    
    def triage(self, file_path):
        """Perform complete triage."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        hashes = self.calculate_hashes(file_path)
        magic_check = self.check_magic_bytes(file_path)
        entropy, high_entropy = self.check_entropy(file_path)
        known_bad, bad_hash_type = self.hash_lookup(hashes)
        suspicious_content = self.scan_suspicious_content(file_path)
        
        # Calculate risk score and verdict
        confidence = 0
        evidence = []
        
        if known_bad:
            confidence = 95
            evidence.append(f"Hash found in known-bad list ({bad_hash_type})")
        
        if high_entropy:
            confidence += 20
            evidence.append(f"High entropy ({entropy}) - likely encrypted/packed")
        
        if magic_check and magic_check.get('mismatch'):
            confidence += 15
            evidence.append(f"Extension mismatch - file is {magic_check['format']}, "
                           f"extension is {magic_check['extension']}")
        
        if magic_check and 'Executable' in magic_check.get('format', ''):
            confidence += 25
            evidence.append("File is executable")
        
        if suspicious_content:
            for category, items in suspicious_content.items():
                if category == 'powershell' or category == 'cmd_execution':
                    confidence += 15
                    evidence.append(f"Found {category} indicators")
                elif category == 'api_calls':
                    confidence += 20
                    evidence.append(f"Found suspicious {category}")
                else:
                    confidence += 5
                    evidence.append(f"Found {category}")
        
        confidence = min(confidence, 100)
        
        # Determine verdict
        if confidence >= 70:
            verdict = 'MALICIOUS'
        elif confidence >= 40:
            verdict = 'SUSPICIOUS'
        else:
            verdict = 'CLEAN'
        
        return {
            'file': os.path.basename(file_path),
            'path': file_path,
            'timestamp': self.timestamp,
            'verdict': verdict,
            'confidence_score': confidence,
            'hashes': hashes,
            'file_magic': magic_check,
            'entropy': entropy,
            'high_entropy': high_entropy,
            'known_bad': known_bad,
            'suspicious_content': suspicious_content,
            'evidence': evidence
        }
    
    def print_report(self, result):
        """Print formatted triage report."""
        print("=" * 80)
        print("UNKNOWN ATTACHMENT TRIAGE REPORT")
        print("=" * 80)
        print(f"File: {result['file']}")
        print(f"Path: {result['path']}")
        print(f"Timestamp: {result['timestamp']}")
        print("")
        
        print("VERDICT")
        print("-" * 80)
        icon = {'MALICIOUS': '🔴', 'SUSPICIOUS': '🟡', 'CLEAN': '✓'}.get(result['verdict'], '?')
        print(f"  {icon} {result['verdict']} (Confidence: {result['confidence_score']}%)")
        print("")
        
        print("ANALYSIS DETAILS")
        print("-" * 80)
        print(f"  Entropy: {result['entropy']}")
        print(f"  Known-Bad: {'Yes' if result['known_bad'] else 'No'}")
        if result['file_magic']:
            print(f"  File Format: {result['file_magic'].get('format')}")
            print(f"  Extension: {result['file_magic'].get('extension')}")
            print(f"  Mismatch: {'Yes' if result['file_magic'].get('mismatch') else 'No'}")
        print("")
        
        if result['evidence']:
            print("EVIDENCE")
            print("-" * 80)
            for i, evidence in enumerate(result['evidence'], 1):
                print(f"  {i}. {evidence}")
        
        print("=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description='Triage unknown email attachments',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 unknown_attachment_triager.py -f attachment.exe
  python3 unknown_attachment_triager.py -f file.bin -j triage_result.json
  python3 unknown_attachment_triager.py -f sample.exe -k known_bad_hashes.txt -j result.json
        """)
    
    parser.add_argument('-f', '--file', required=True, help='Attachment file to triage')
    parser.add_argument('-k', '--known-bad', help='File with known-bad hash list')
    parser.add_argument('-j', '--json', help='Output JSON file')
    
    args = parser.parse_args()
    
    try:
        triager = UnknownAttachmentTriager(args.known_bad)
        result = triager.triage(args.file)
        
        triager.print_report(result)
        
        if args.json:
            with open(args.json, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"[+] JSON report written to: {args.json}")
    
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
