#!/usr/bin/env python3
"""
Suspicious String Identifier - Identify suspicious strings in binary/text files.
Maintain categorized suspicious string database: C2 indicators, injection, evasion,
credentials, persistence. Scan file, report hits with category and context.
"""

import sys
import os
import argparse
import re
import json
from datetime import datetime


class SuspiciousStringIdentifier:
    """Identify suspicious strings in files."""
    
    SUSPICIOUS_STRINGS = {
        'c2_indicators': {
            'patterns': [
                r'beacon',
                r'checkin',
                r'callback',
                r'c2_server',
                r'command.?server',
                r'control.?server',
                r'implant',
            ],
            'severity': 'high'
        },
        'injection': {
            'patterns': [
                r'VirtualAlloc',
                r'VirtualAllocEx',
                r'WriteProcessMemory',
                r'CreateRemoteThread',
                r'SetWindowsHookEx',
                r'QueueUserAPC',
                r'NtWriteVirtualMemory',
            ],
            'severity': 'high'
        },
        'evasion': {
            'patterns': [
                r'IsDebuggerPresent',
                r'CheckRemoteDebuggerPresent',
                r'GetTickCount',
                r'QueryPerformanceCounter',
                r'NtQueryInformationProcess',
                r'FindWindowA',
                r'GetModuleHandle.*kernel32',
            ],
            'severity': 'medium'
        },
        'credentials': {
            'patterns': [
                r'password',
                r'passwd',
                r'pwd',
                r'credential',
                r'secret',
                r'api_key',
                r'apikey',
                r'token',
                r'private_key',
                r'username',
            ],
            'severity': 'medium'
        },
        'persistence': {
            'patterns': [
                r'HKEY_LOCAL_MACHINE.*Run',
                r'HKEY_CURRENT_USER.*Run',
                r'RunOnce',
                r'Startup',
                r'startupfolder',
                r'startup',
                r'schtasks',
                r'scheduled.?task',
            ],
            'severity': 'high'
        },
        'network': {
            'patterns': [
                r'socket',
                r'connect',
                r'send',
                r'recv',
                r'http.*post',
                r'http.*get',
                r'urldownloadtofile',
                r'internetopen',
            ],
            'severity': 'medium'
        },
        'file_operations': {
            'patterns': [
                r'CreateFileA',
                r'CreateFileW',
                r'WriteFile',
                r'ReadFile',
                r'DeleteFileA',
                r'DeleteFileW',
                r'CopyFileA',
                r'CopyFileW',
            ],
            'severity': 'low'
        }
    }
    
    def __init__(self):
        self.timestamp = datetime.now().isoformat()
    
    def extract_strings(self, file_path, min_len=4):
        """Extract ASCII strings from file."""
        strings = []
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            current = []
            offset = 0
            for i, byte in enumerate(content):
                if 0x20 <= byte <= 0x7E:
                    current.append((chr(byte), i - len(current)))
                else:
                    if len(current) >= min_len:
                        s = ''.join([c[0] for c in current])
                        strings.append({'string': s, 'offset': current[0][1]})
                    current = []
        
        except Exception:
            pass
        
        return strings
    
    def scan_suspicious_strings(self, strings):
        """Scan strings for suspicious patterns."""
        findings = {}
        
        for category, config in self.SUSPICIOUS_STRINGS.items():
            matches = []
            for pattern in config['patterns']:
                for str_obj in strings:
                    try:
                        if re.search(pattern, str_obj['string'], re.IGNORECASE):
                            match = {
                                'string': str_obj['string'],
                                'offset': str_obj.get('offset', 0),
                                'pattern': pattern
                            }
                            if match not in matches:
                                matches.append(match)
                    except Exception:
                        pass
            
            if matches:
                findings[category] = {
                    'severity': config['severity'],
                    'count': len(matches),
                    'matches': matches[:10]
                }
        
        return findings
    
    def calculate_risk_score(self, findings):
        """Calculate overall risk score from findings."""
        score = 0
        
        for category, data in findings.items():
            count = data['count']
            severity = data['severity']
            
            if severity == 'high':
                score += count * 15
            elif severity == 'medium':
                score += count * 8
            else:
                score += count * 3
        
        return min(score, 100)
    
    def process_file(self, file_path):
        """Process file and identify suspicious strings."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        strings = self.extract_strings(file_path)
        findings = self.scan_suspicious_strings(strings)
        risk_score = self.calculate_risk_score(findings)
        
        result = {
            'file': file_path,
            'file_size': os.path.getsize(file_path),
            'timestamp': self.timestamp,
            'total_strings': len(strings),
            'suspicious_categories': len(findings),
            'risk_score': risk_score,
            'findings': findings
        }
        
        return result
    
    def print_report(self, result):
        """Print formatted detection report."""
        print("=" * 90)
        print("SUSPICIOUS STRING IDENTIFICATION REPORT")
        print("=" * 90)
        print(f"File: {result['file']}")
        print(f"File Size: {result['file_size']} bytes")
        print(f"Timestamp: {result['timestamp']}")
        print(f"Total Strings: {result['total_strings']}")
        print("")
        
        print("RISK ASSESSMENT")
        print("-" * 90)
        print(f"  Risk Score: {result['risk_score']}/100")
        print(f"  Suspicious Categories: {result['suspicious_categories']}")
        print("")
        
        if not result['findings']:
            print("[*] No suspicious strings identified")
            print("=" * 90)
            return
        
        print("FINDINGS BY CATEGORY")
        print("-" * 90)
        
        # Sort by severity
        severity_order = {'high': 0, 'medium': 1, 'low': 2}
        sorted_findings = sorted(
            result['findings'].items(),
            key=lambda x: severity_order.get(x[1]['severity'], 3)
        )
        
        for category, data in sorted_findings:
            severity_icon = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}.get(data['severity'], '?')
            print(f"\n{severity_icon} {category.upper()} (severity: {data['severity']})")
            print(f"  Count: {data['count']}")
            print(f"  Matches:")
            
            for match in data['matches'][:5]:
                display = match['string'][:70]
                if len(match['string']) > 70:
                    display += "..."
                print(f"    • {display}")
                print(f"      Offset: 0x{match['offset']:08x}, Pattern: {match['pattern']}")
            
            if data['count'] > 5:
                print(f"    ... and {data['count'] - 5} more")
        
        print("\n" + "=" * 90)


def main():
    parser = argparse.ArgumentParser(
        description='Identify suspicious strings in binary/text files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 suspicious_string_identifier.py -f malware.bin
  python3 suspicious_string_identifier.py -f sample.exe -j findings.json
        """)
    
    parser.add_argument('-f', '--file', required=True, help='File to scan')
    parser.add_argument('-j', '--json', help='Output JSON file')
    
    args = parser.parse_args()
    
    try:
        identifier = SuspiciousStringIdentifier()
        result = identifier.process_file(args.file)
        
        identifier.print_report(result)
        
        if args.json:
            with open(args.json, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"[+] JSON report written to: {args.json}")
    
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
