#!/usr/bin/env python3
"""
Cobalt Strike Beacon Config Extractor - Extract Cobalt Strike beacon indicators.
Search for: named pipes (msagent_, MSSE-, postex_), malleable C2 patterns,
XOR key 0x69 (default), sleep mask patterns, config blocks with C2 server, port,
jitter, user-agent, HTTP method, URI patterns. Report all with file offsets.
Note: static analysis only, no execution.
"""

import sys
import os
import argparse
import re
import json
from datetime import datetime


class CobaltStrikeBeaconConfigExtractor:
    """Extract Cobalt Strike beacon indicators from binaries."""
    
    INDICATORS = {
        'named_pipes': [
            r'\\\.\\pipe\\.*msagent_',
            r'\\\.\\pipe\\.*MSSE',
            r'\\\.\\pipe\\.*postex',
            r'\\\.\\pipe\\.*win',
            r'\\\.\\pipe\\.*status',
        ],
        'beacon_strings': [
            r'beacon',
            r'implant',
            r'sleeper',
            r'stager',
            r'reflective',
        ],
        'c2_indicators': [
            r'__c2_server__',
            r'__c2_port__',
            r'__jitter__',
            r'__useragent__',
            r'__host_header__',
            r'__user_agent__',
        ],
        'http_methods': [
            r'GET\s+HTTP',
            r'POST\s+HTTP',
            r'PUT\s+HTTP',
            r'HEAD\s+HTTP',
        ],
        'uri_patterns': [
            r'/api/[a-z0-9]+',
            r'/submit\\.php',
            r'/index\\.php',
            r'/.*\\.gif',
            r'/.*\\.jpg',
        ]
    }
    
    def __init__(self):
        self.timestamp = datetime.now().isoformat()
    
    def read_binary(self, file_path):
        """Read binary file."""
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except Exception as e:
            raise Exception(f"Failed to read file: {e}")
    
    def extract_strings(self, data, min_len=4):
        """Extract printable ASCII strings."""
        strings = []
        current = []
        offset_start = 0
        
        for offset, byte in enumerate(data):
            if 0x20 <= byte <= 0x7E:
                if not current:
                    offset_start = offset
                current.append(chr(byte))
            else:
                if len(current) >= min_len:
                    strings.append({
                        'string': ''.join(current),
                        'offset': offset_start
                    })
                current = []
        
        if len(current) >= min_len:
            strings.append({
                'string': ''.join(current),
                'offset': offset_start
            })
        
        return strings
    
    def search_indicators(self, strings):
        """Search for Cobalt Strike indicators."""
        findings = {}
        
        for category, patterns in self.INDICATORS.items():
            matches = []
            for pattern in patterns:
                for str_obj in strings:
                    try:
                        if re.search(pattern, str_obj['string'], re.IGNORECASE):
                            match = {
                                'string': str_obj['string'][:100],
                                'offset': str_obj['offset'],
                                'pattern': pattern
                            }
                            if match not in matches:
                                matches.append(match)
                    except Exception:
                        pass
            
            if matches:
                findings[category] = matches[:10]
        
        return findings
    
    def search_xor_keys(self, data):
        """Search for XOR key patterns (default 0x69)."""
        xor_keys = []
        
        # Look for 0x69 (default beacon XOR key) patterns
        default_key = 0x69
        pattern = bytes([default_key]) * 4
        
        for offset in range(0, len(data) - len(pattern)):
            if data[offset:offset+len(pattern)] == pattern:
                xor_keys.append({
                    'key': hex(default_key),
                    'offset': offset,
                    'type': 'default_key'
                })
        
        return xor_keys[:20]
    
    def search_config_blocks(self, data):
        """Search for config block patterns."""
        config_blocks = []
        
        # Look for potential config markers
        markers = [
            b'aes256',
            b'config',
            b'beacon_type',
            b'spawn64',
            b'spawn32',
            b'jitter',
            b'sleep',
        ]
        
        for marker in markers:
            offset = 0
            while True:
                pos = data.find(marker, offset)
                if pos == -1:
                    break
                
                context_start = max(0, pos - 50)
                context_end = min(len(data), pos + 100)
                context = data[context_start:context_end]
                
                # Try to decode as text
                try:
                    decoded = context.decode('utf-8', errors='ignore')
                    config_blocks.append({
                        'marker': marker.decode('utf-8'),
                        'offset': pos,
                        'context': decoded[:100]
                    })
                except Exception:
                    pass
                
                offset = pos + 1
        
        return config_blocks[:15]
    
    def analyze_file(self, file_path):
        """Analyze file for Cobalt Strike indicators."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        data = self.read_binary(file_path)
        strings = self.extract_strings(data)
        indicators = self.search_indicators(strings)
        xor_keys = self.search_xor_keys(data)
        config_blocks = self.search_config_blocks(data)
        
        return {
            'file': file_path,
            'file_size': len(data),
            'timestamp': self.timestamp,
            'indicators_found': len(indicators) > 0,
            'indicators': indicators,
            'xor_keys': xor_keys,
            'config_blocks': config_blocks,
            'risk_score': self._calculate_risk(indicators, xor_keys, config_blocks)
        }
    
    def _calculate_risk(self, indicators, xor_keys, config_blocks):
        """Calculate risk score."""
        score = 0
        
        if 'named_pipes' in indicators:
            score += 30
        if 'beacon_strings' in indicators:
            score += 25
        if 'c2_indicators' in indicators:
            score += 30
        if xor_keys:
            score += 15
        if config_blocks:
            score += 15
        
        return min(score, 100)
    
    def print_report(self, result):
        """Print formatted extraction report."""
        print("=" * 90)
        print("COBALT STRIKE BEACON CONFIG EXTRACTION REPORT")
        print("=" * 90)
        print(f"File: {os.path.basename(result['file'])}")
        print(f"Path: {result['file']}")
        print(f"File Size: {result['file_size']} bytes")
        print(f"Timestamp: {result['timestamp']}")
        print("")
        
        print("ANALYSIS SUMMARY")
        print("-" * 90)
        print(f"  Indicators Found: {'Yes' if result['indicators_found'] else 'No'}")
        print(f"  Risk Score: {result['risk_score']}/100")
        
        if result['risk_score'] >= 70:
            print(f"  Assessment: ⚠️  HIGHLY SUSPICIOUS - Likely Cobalt Strike beacon")
        elif result['risk_score'] >= 40:
            print(f"  Assessment: ⚠️  SUSPICIOUS - Possible Cobalt Strike indicators")
        else:
            print(f"  Assessment: ℹ️  No definitive Cobalt Strike indicators found")
        print("")
        
        if result['indicators']:
            print("INDICATORS DETECTED")
            print("-" * 90)
            for category, matches in result['indicators'].items():
                print(f"\n  {category.upper()} ({len(matches)} matches):")
                for match in matches[:5]:
                    print(f"    • {match['string'][:70]}")
                    print(f"      Offset: 0x{match['offset']:08x}")
                if len(matches) > 5:
                    print(f"    ... and {len(matches) - 5} more")
        
        if result['xor_keys']:
            print(f"\nXOR KEYS FOUND")
            print("-" * 90)
            print(f"  Key 0x69 (default) found at {len(result['xor_keys'])} locations:")
            for key_info in result['xor_keys'][:5]:
                print(f"    Offset: 0x{key_info['offset']:08x}")
        
        if result['config_blocks']:
            print(f"\nCONFIG BLOCK MARKERS")
            print("-" * 90)
            for block in result['config_blocks'][:10]:
                print(f"  Marker: {block['marker']}")
                print(f"  Offset: 0x{block['offset']:08x}")
                print(f"  Context: {block['context'][:60]}")
        
        print("\n" + "=" * 90)


def main():
    parser = argparse.ArgumentParser(
        description='Extract Cobalt Strike beacon indicators from binaries',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cobalt_strike_beacon_config_extractor.py -f beacon.exe
  python3 cobalt_strike_beacon_config_extractor.py -f malware.bin -j indicators.json
  
Note: This tool performs static analysis only. No execution or dynamic behavior analysis.
        """)
    
    parser.add_argument('-f', '--file', required=True, help='Binary file to analyze')
    parser.add_argument('-j', '--json', help='Output JSON file')
    
    args = parser.parse_args()
    
    try:
        extractor = CobaltStrikeBeaconConfigExtractor()
        result = extractor.analyze_file(args.file)
        
        extractor.print_report(result)
        
        if args.json:
            with open(args.json, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"\n[+] JSON report written to: {args.json}")
    
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
