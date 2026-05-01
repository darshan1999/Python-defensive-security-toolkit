#!/usr/bin/env python3
"""
Obfuscated Code Detector - Detect obfuscated code in script files.
Check for: base64 strings, hex encoded (\\x41\\x42...), long single lines >500 chars,
eval/exec of variables, character substitution patterns, excessive concatenation,
ROT13 patterns, XOR on byte arrays. Score each indicator. Report likelihood with evidence.
"""

import sys
import os
import argparse
import re
import json
import base64
from datetime import datetime


class ObfuscatedCodeDetector:
    """Detect obfuscated code in script files."""
    
    SUPPORTED_EXTENSIONS = {'.py', '.js', '.php', '.ps1', '.vbs', '.sh', '.pl'}
    
    def __init__(self):
        self.timestamp = datetime.now().isoformat()
    
    def is_supported_file(self, file_path):
        """Check if file type is supported."""
        ext = os.path.splitext(file_path)[1].lower()
        return ext in self.SUPPORTED_EXTENSIONS
    
    def read_file_content(self, file_path):
        """Read file content."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return None
    
    def check_base64_strings(self, content):
        """Check for base64 encoded strings."""
        matches = []
        pattern = r'[A-Za-z0-9+/]{32,}={0,2}'
        
        for match in re.finditer(pattern, content):
            string = match.group(0)
            try:
                decoded = base64.b64decode(string).decode('utf-8', errors='ignore')
                if len(decoded) > 10 and not all(c.isspace() for c in decoded):
                    matches.append({
                        'type': 'base64',
                        'encoded': string[:60],
                        'decoded_preview': decoded[:50]
                    })
            except Exception:
                pass
        
        return matches[:5]
    
    def check_hex_encoding(self, content):
        """Check for hex encoded strings (\\x41\\x42...)."""
        pattern = r'(\\x[0-9a-fA-F]{2}){4,}'
        matches = re.findall(pattern, content)
        
        return len(matches) > 0, len(matches)
    
    def check_long_lines(self, content):
        """Check for suspiciously long single lines (>500 chars)."""
        lines = content.split('\n')
        long_lines = [len(line) for line in lines if len(line) > 500]
        
        return len(long_lines) > 0, len(long_lines)
    
    def check_eval_exec(self, content):
        """Check for eval/exec of variables."""
        patterns = [
            r'eval\s*\(',
            r'exec\s*\(',
            r'eval\s*\{',
            r'exec\s*\{',
            r'interpret\s*\(',
            r'compile\s*\(',
        ]
        
        matches = []
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_start = content.rfind('\n', 0, match.start()) + 1
                line_end = content.find('\n', match.end())
                line = content[line_start:line_end].strip()[:80]
                matches.append(line)
        
        return len(set(matches)) > 0, len(set(matches))
    
    def check_concatenation(self, content):
        """Check for excessive string concatenation."""
        # Look for patterns like str1 + str2 + str3...
        pattern = r'["\'][^"\']*["\'](\s*[\+]\s*["\'][^"\']*["\']){3,}'
        matches = re.findall(pattern, content)
        
        return len(matches) > 0, len(matches)
    
    def check_rot13_patterns(self, content):
        """Check for ROT13 patterns."""
        # Check for rot13 or similar rotation functions
        rot_patterns = [
            r'rot13',
            r'ROT13',
            r'caesar',
            r'rotation',
        ]
        
        count = 0
        for pattern in rot_patterns:
            count += len(re.findall(pattern, content, re.IGNORECASE))
        
        return count > 0, count
    
    def check_xor_patterns(self, content):
        """Check for XOR operations on byte arrays."""
        xor_patterns = [
            r'\s\^=',
            r'\sxor\s',
            r'bytes\..*xor',
            r'\[.*\]\s*\^\s*[0-9a-fA-Fx]+',
        ]
        
        count = 0
        for pattern in xor_patterns:
            count += len(re.findall(pattern, content, re.IGNORECASE))
        
        return count > 0, count
    
    def detect_obfuscation(self, file_path):
        """Detect obfuscation in file."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not self.is_supported_file(file_path):
            raise ValueError(f"Unsupported file type. Supported: {', '.join(self.SUPPORTED_EXTENSIONS)}")
        
        content = self.read_file_content(file_path)
        if not content:
            raise Exception("Failed to read file content")
        
        indicators = {}
        evidence = []
        score = 0
        
        # Check base64
        base64_matches = self.check_base64_strings(content)
        if base64_matches:
            indicators['base64'] = len(base64_matches)
            score += 15
            for match in base64_matches[:2]:
                evidence.append(f"Base64: {match['decoded_preview'][:50]}")
        
        # Check hex encoding
        has_hex, hex_count = self.check_hex_encoding(content)
        if has_hex:
            indicators['hex_encoding'] = hex_count
            score += 20
            evidence.append(f"Hex encoding: {hex_count} occurrences")
        
        # Check long lines
        has_long, long_count = self.check_long_lines(content)
        if has_long:
            indicators['long_lines'] = long_count
            score += 10
            evidence.append(f"Long lines (>500 chars): {long_count}")
        
        # Check eval/exec
        has_eval, eval_count = self.check_eval_exec(content)
        if has_eval:
            indicators['eval_exec'] = eval_count
            score += 25
            evidence.append(f"eval/exec operations: {eval_count}")
        
        # Check concatenation
        has_concat, concat_count = self.check_concatenation(content)
        if has_concat:
            indicators['concatenation'] = concat_count
            score += 10
            evidence.append(f"Excessive concatenation: {concat_count} patterns")
        
        # Check ROT13
        has_rot13, rot13_count = self.check_rot13_patterns(content)
        if has_rot13:
            indicators['rot13'] = rot13_count
            score += 15
            evidence.append(f"ROT13 patterns: {rot13_count}")
        
        # Check XOR
        has_xor, xor_count = self.check_xor_patterns(content)
        if has_xor:
            indicators['xor'] = xor_count
            score += 20
            evidence.append(f"XOR patterns: {xor_count}")
        
        score = min(score, 100)
        
        return {
            'file': file_path,
            'filename': os.path.basename(file_path),
            'timestamp': self.timestamp,
            'obfuscation_score': score,
            'likelihood': self._get_likelihood(score),
            'indicators': indicators,
            'evidence': evidence
        }
    
    def _get_likelihood(self, score):
        """Get obfuscation likelihood."""
        if score >= 70:
            return "Very High"
        elif score >= 50:
            return "High"
        elif score >= 30:
            return "Moderate"
        else:
            return "Low"
    
    def print_report(self, result):
        """Print formatted detection report."""
        print("=" * 80)
        print("OBFUSCATED CODE DETECTION REPORT")
        print("=" * 80)
        print(f"File: {result['filename']}")
        print(f"Path: {result['file']}")
        print(f"Timestamp: {result['timestamp']}")
        print("")
        
        print("OBFUSCATION ASSESSMENT")
        print("-" * 80)
        icon = {'Very High': '🔴', 'High': '🟠', 'Moderate': '🟡', 'Low': '✓'}.get(result['likelihood'])
        print(f"  {icon} Score: {result['obfuscation_score']}/100")
        print(f"  Likelihood: {result['likelihood']}")
        print("")
        
        if result['indicators']:
            print("OBFUSCATION INDICATORS")
            print("-" * 80)
            for indicator, count in result['indicators'].items():
                print(f"  ✓ {indicator}: {count}")
        
        if result['evidence']:
            print("")
            print("EVIDENCE")
            print("-" * 80)
            for i, item in enumerate(result['evidence'], 1):
                print(f"  {i}. {item[:75]}")
        
        print("=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description='Detect obfuscated code in script files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 obfuscated_code_detector.py -f script.py
  python3 obfuscated_code_detector.py -f payload.ps1 -j report.json
  python3 obfuscated_code_detector.py -f malware.php -o results.json
        """)
    
    parser.add_argument('-f', '--file', required=True, help='Script file to analyze')
    parser.add_argument('-j', '--json', '-o', '--output', dest='output', help='Output JSON file')
    
    args = parser.parse_args()
    
    try:
        detector = ObfuscatedCodeDetector()
        result = detector.detect_obfuscation(args.file)
        
        detector.print_report(result)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"[+] JSON report written to: {args.output}")
    
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
