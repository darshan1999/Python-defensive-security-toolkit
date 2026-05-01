#!/usr/bin/env python3
"""
YARA Rule Generator - Generates YARA rules from suspicious files automatically.
Extracts unique strings, byte sequences, and file characteristics for rule creation.
"""

import sys
import os
import argparse
import re
from pathlib import Path
from datetime import datetime

def extract_strings(filepath: str, min_length: int = 8) -> set:
    """Extract unique strings from file for YARA rule."""
    strings = set()
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
            
        # Extract printable ASCII strings
        for match in re.finditer(b'[\x20-\x7e]{' + str(min_length).encode() + b',}', content):
            try:
                s = match.group(0).decode('ascii')
                if len(s) > min_length and not s.isspace():
                    strings.add(s)
            except:
                pass
    except:
        pass
    
    return strings

def extract_header_bytes(filepath: str, num_bytes: int = 32) -> str:
    """Extract first N bytes as hex for YARA rule."""
    try:
        with open(filepath, 'rb') as f:
            data = f.read(num_bytes)
            return ' '.join(f'{b:02x}' for b in data)
    except:
        return ""

def generate_yara_rule(filepath: str, output_file: str = None) -> bool:
    """Generate YARA rule from file."""
    if not os.path.isfile(filepath):
        print(f"Error: {filepath} not found", file=sys.stderr)
        return False
    
    try:
        filename = Path(filepath).stem
        file_size = os.path.getsize(filepath)
        
        # Extract strings and bytes
        strings = extract_strings(filepath)
        header_bytes = extract_header_bytes(filepath)
        
        # Limit to top 20 unique strings
        top_strings = sorted(strings, key=len, reverse=True)[:20]
        
        # Generate YARA rule
        rule = f"""rule {filename}_malware {{
    meta:
        description = "Auto-generated rule for {filename}"
        date = "{datetime.now().isoformat()}"
        author = "Security Analyst"
        file_size = "{file_size} bytes"
    
    strings:
"""
        
        # Add string conditions
        for i, s in enumerate(top_strings):
            # Escape special characters for YARA
            escaped = s.replace('\\', '\\\\').replace('"', '\\"')
            rule += f'        $str{i} = "{escaped}" ascii\n'
        
        # Add header bytes if available
        if header_bytes:
            rule += f'        $header = {{ {header_bytes} }}\n'
        
        rule += f"""
    condition:
        any of them
}}"""
        
        # Output to file
        if output_file is None:
            output_file = f"{filename}.yar"
        
        with open(output_file, 'w') as f:
            f.write(rule)
        
        print(f"[+] YARA rule generated: {output_file}")
        print(f"    Strings extracted: {len(top_strings)}")
        print(f"    File size: {file_size} bytes")
        
        return True
        
    except Exception as e:
        print(f"Error generating rule: {e}", file=sys.stderr)
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Generate YARA rules from suspicious files",
        epilog="Example: python3 yara_rule_generator.py suspicious.exe --output rules.yar"
    )
    parser.add_argument("file", help="File to analyze")
    parser.add_argument("--output", help="Output YARA file (default: filename.yar)")
    parser.add_argument("--min-length", type=int, default=8, help="Minimum string length")
    
    args = parser.parse_args()
    
    return 0 if generate_yara_rule(args.file, args.output) else 1

if __name__ == "__main__":
    sys.exit(main())
