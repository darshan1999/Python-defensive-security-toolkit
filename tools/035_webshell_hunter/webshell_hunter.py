#!/usr/bin/env python3
"""
Web Shell Hunter - Advanced PHP/JSP/ASP web shell detection.

Scans web directories for suspicious patterns:
- base64_decode + eval combinations
- system/exec/passthru/shell_exec functions
- Obfuscated single-character variables ($_GET, $_, $a, etc.)
- _REQUEST and _SERVER abuse
- Hex-encoded strings
- High entropy code sections

Output: Risk-scored file listing (0-100), flags suspicious files >40 threshold.
"""

import argparse
import os
import re
import math
from pathlib import Path
from collections import Counter
from datetime import datetime
import json

class WebShellHunter:
    """Detects web shells using pattern analysis and entropy scoring."""
    
    SHELL_EXTENSIONS = {'.php', '.php3', '.php4', '.php5', '.phtml', '.jsp', '.jspx', '.asp', '.aspx'}
    
    DANGEROUS_FUNCTIONS = {
        'system', 'exec', 'shell_exec', 'passthru', 'eval', 'base64_decode',
        'assert', 'create_function', 'include', 'require', 'popen', 'proc_open'
    }
    
    SUSPICIOUS_VARS = {
        '$_REQUEST', '$_GET', '$_POST', '$_SERVER', '$_FILES',
        '$_', '$a', '$b', '$c', '$x', '$y', '$z', '$p'
    }
    
    def __init__(self, threshold=40):
        self.threshold = threshold
        self.results = []
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0
        freq = Counter(data)
        entropy = 0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy
    
    def score_file(self, filepath):
        """Analyze file and return risk score (0-100)."""
        score = 0
        details = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            return 0, [f"Cannot read: {e}"]
        
        # Check for base64_decode + eval
        if re.search(r'base64_decode\s*\(\s*\$_', content):
            score += 30
            details.append("base64_decode with $_REQUEST variable")
        
        # Check for dangerous functions
        for func in self.DANGEROUS_FUNCTIONS:
            if func + '(' in content:
                score += 10
                details.append(f"Dangerous function: {func}")
                if score > 100:
                    break
        
        # Check for obfuscated variables
        obf_count = sum(1 for var in self.SUSPICIOUS_VARS if var in content)
        if obf_count > 3:
            score += 20
            details.append(f"Multiple suspicious variables: {obf_count}")
        
        # Check for hex strings (common obfuscation)
        hex_pattern = r'0x[0-9a-fA-F]{4,}'
        if len(re.findall(hex_pattern, content)) > 5:
            score += 15
            details.append("Hex-encoded strings detected")
        
        # Check entropy of code sections
        code_blocks = re.findall(r'\$[a-zA-Z_]\w*\s*=\s*["\']([^"\']{20,})["\']', content)
        for block in code_blocks:
            entropy = self.calculate_entropy(block)
            if entropy > 6.5:
                score += 10
                details.append(f"High-entropy obfuscated code")
                break
        
        # Check for common web shell signatures
        if re.search(r'($_GET|$_POST|$_REQUEST)\s*\[\s*[\'"][\'"]?\s*\]', content):
            score += 15
            details.append("Empty parameter access (shell signature)")
        
        return min(100, score), details
    
    def scan_directory(self, directory):
        """Recursively scan directory for web shells."""
        for root, dirs, files in os.walk(directory):
            for file in files:
                if Path(file).suffix.lower() in self.SHELL_EXTENSIONS:
                    filepath = os.path.join(root, file)
                    score, details = self.score_file(filepath)
                    
                    if score >= self.threshold:
                        self.results.append({
                            'file': filepath,
                            'risk_score': score,
                            'flagged': score >= self.threshold,
                            'details': details,
                            'timestamp': datetime.now().isoformat()
                        })
        
        self.results.sort(key=lambda x: x['risk_score'], reverse=True)
    
    def report(self):
        """Generate detection report."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'threshold': self.threshold,
            'total_suspicious': len(self.results),
            'detections': self.results,
            'summary': f"Found {len(self.results)} files with risk score >= {self.threshold}"
        }
        return report

def main():
    parser = argparse.ArgumentParser(
        description='Advanced web shell detection in PHP/JSP/ASP files.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 webshell_hunter.py --directory /var/www
  python3 webshell_hunter.py --directory /var/www/html --threshold 50
  python3 webshell_hunter.py --directory /app --output shells.json --threshold 30
        """)
    
    parser.add_argument('--directory', type=str, required=True, help='Directory to scan')
    parser.add_argument('--threshold', type=int, default=40, help='Risk score threshold (0-100, default 40)')
    parser.add_argument('--output', type=str, help='Output JSON file')
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.directory):
        print(f"[!] Invalid directory: {args.directory}")
        return
    
    hunter = WebShellHunter(threshold=args.threshold)
    print(f"[*] Scanning {args.directory} for web shells...", flush=True)
    hunter.scan_directory(args.directory)
    
    report = hunter.report()
    print(json.dumps(report, indent=2))
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")

if __name__ == "__main__":
    main()
