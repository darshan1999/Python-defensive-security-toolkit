#!/usr/bin/env python3
"""
Base64 Decoder - Detects and decodes base64 encoded strings in files.
Recursively decodes multiple levels and classifies decoded content.
"""

import sys
import base64
import re
import argparse
from pathlib import Path

def is_base64(s: str) -> bool:
    """Check if string is valid base64."""
    if len(s) % 4 != 0:
        return False
    try:
        return isinstance(base64.b64decode(s, validate=True), bytes)
    except:
        return False

def decode_base64_recursive(encoded: str, max_depth: int = 3, depth: int = 0) -> list:
    """Recursively decode base64 strings."""
    results = []
    
    if depth >= max_depth or len(encoded) < 20:
        return results
    
    try:
        decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
        
        result = {
            'depth': depth,
            'encoded': encoded[:50],
            'decoded': decoded[:200],
            'type': 'unknown'
        }
        
        # Classify decoded content
        if decoded.startswith('MZ'):
            result['type'] = 'PE_EXECUTABLE'
        elif decoded.startswith(b'%PDF'):
            result['type'] = 'PDF'
        elif 'http://' in decoded or 'https://' in decoded:
            result['type'] = 'URL'
            result['decoded'] = re.findall(r'https?://[^\s"\'<>]+', decoded)
        elif re.search(r'\b\d+\.\d+\.\d+\.\d+\b', decoded):
            result['type'] = 'IP_ADDRESSES'
            result['decoded'] = re.findall(r'\d+\.\d+\.\d+\.\d+', decoded)
        else:
            result['type'] = 'TEXT'
        
        results.append(result)
        
        # Try recursive decoding
        if is_base64(decoded) and depth < max_depth - 1:
            results.extend(decode_base64_recursive(decoded, max_depth, depth + 1))
            
    except:
        pass
    
    return results

def extract_base64(text: str) -> set:
    """Extract base64 strings from text."""
    # Look for sequences of >20 base64 characters
    pattern = r'[A-Za-z0-9+/]{20,}(?:={0,2})'
    matches = set()
    
    for match in re.finditer(pattern, text):
        candidate = match.group(0)
        if is_base64(candidate):
            matches.add(candidate)
    
    return matches

def main():
    parser = argparse.ArgumentParser(
        description="Detect and decode base64 encoded strings in files",
        epilog="Example: python3 base64_decoder.py malware.bin --output decoded.json"
    )
    parser.add_argument("input", nargs='?', default='-', help="Input file or - for stdin")
    parser.add_argument("--output", help="Output JSON file")
    parser.add_argument("--max-depth", type=int, default=3, help="Max recursive decoding depth")
    
    args = parser.parse_args()
    
    try:
        # Read input
        if args.input == '-':
            data = sys.stdin.read()
        else:
            if not Path(args.input).exists():
                print(f"Error: {args.input} not found", file=sys.stderr)
                return 1
            with open(args.input, 'rb') as f:
                data = f.read().decode('utf-8', errors='ignore')
        
        # Extract base64 strings
        base64_strings = extract_base64(data)
        
        print(f"[+] Base64 Decoding Report")
        print(f"    Base64 strings found: {len(base64_strings)}")
        
        all_decoded = []
        for b64 in list(base64_strings)[:20]:  # Limit to first 20
            decoded_chain = decode_base64_recursive(b64, args.max_depth)
            all_decoded.extend(decoded_chain)
            
            if decoded_chain:
                print(f"\n[+] Decoded base64 string (truncated):")
                print(f"    Encoded: {b64[:60]}...")
                for item in decoded_chain:
                    print(f"    Level {item['depth']}: [{item['type']}] {str(item['decoded'])[:100]}")
        
        # Alert on suspicious content
        suspicious_count = sum(1 for item in all_decoded 
                              if item['type'] in ['PE_EXECUTABLE', 'URL', 'IP_ADDRESSES'])
        
        if suspicious_count > 0:
            print(f"\n[!] SUSPICIOUS: {suspicious_count} items contain potential IOCs or executables")
            return 1
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
