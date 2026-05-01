#!/usr/bin/env python3
"""
Magic Byte Validator - Validates file format by checking magic bytes/file signatures.
Detects mismatches between file extensions and actual format (suspicious indicators).
"""

import sys
import os
import argparse
from pathlib import Path

MAGIC_BYTES = {
    b'\x25\x50\x44\x46': ('PDF', '.pdf'),
    b'\x4d\x5a': ('PE/EXE/DLL', '.exe|.dll|.sys'),
    b'\x50\x4b': ('ZIP', '.zip|.docx|.xlsx|.pptx|.jar'),
    b'\x1f\x8b': ('GZIP', '.gz|.gzip'),
    b'\x89\x50\x4e\x47': ('PNG', '.png'),
    b'\xff\xd8\xff': ('JPEG', '.jpg|.jpeg'),
    b'\x47\x49\x46': ('GIF', '.gif'),
    b'\x42\x4d': ('BMP', '.bmp'),
    b'\xff\xfb': ('MP3', '.mp3'),
    b'\x7f\x45\x4c\x46': ('ELF', '.elf|.o|.so'),
    b'\xca\xfe\xba\xbe': ('Java Class', '.class'),
    b'\xce\xfa\xed\xfe': ('Mach-O', '.dylib|.app'),
    b'\x52\x61\x72': ('RAR', '.rar'),
    b'\x7a\x37': ('7-Zip', '.7z'),
    b'\x75\x73\x74\x61\x72': ('TAR', '.tar'),
    b'\x7b\x5c\x72\x74\x66': ('RTF', '.rtf'),
    b'\xd0\xcf\x11\xe0': ('OLE/DOC/XLS', '.doc|.xls|.ppt'),
}

def detect_file_format(filepath: str) -> tuple:
    """Detect file format by magic bytes. Returns (format_name, suggested_ext)."""
    try:
        with open(filepath, 'rb') as f:
            header = f.read(16)
    except:
        return (None, None)
    
    # Check magic bytes
    for magic, (format_name, suggested_ext) in MAGIC_BYTES.items():
        if header.startswith(magic):
            return (format_name, suggested_ext)
    
    return (None, None)

def validate_files(target: str) -> list:
    """Validate file format for a file or directory."""
    results = []
    
    if os.path.isfile(target):
        files = [target]
    elif os.path.isdir(target):
        files = []
        for root, dirs, filenames in os.walk(target):
            for filename in filenames:
                files.append(os.path.join(root, filename))
    else:
        print(f"Error: {target} not found", file=sys.stderr)
        return results
    
    print(f"[*] Validating {len(files)} file(s)...")
    
    for filepath in files:
        try:
            filename = os.path.basename(filepath)
            ext = Path(filename).suffix.lower()
            
            format_name, suggested_exts = detect_file_format(filepath)
            
            if format_name:
                # Check if extension matches detected format
                match = 'yes' if ext in f'{suggested_exts}'.split('|') else 'no'
                
                result = {
                    'file': filename,
                    'extension': ext,
                    'detected_format': format_name,
                    'match': match,
                    'suspicious': match == 'no'
                }
                
                results.append(result)
                
                if match == 'no':
                    print(f"[!] MISMATCH: {filename}")
                    print(f"    Extension: {ext}")
                    print(f"    Format: {format_name} (expected: {suggested_exts})")
                else:
                    print(f"[+] OK: {filename} ({format_name})")
            else:
                print(f"[?] UNKNOWN: {filename} - no recognized format")
                
        except Exception as e:
            pass
    
    return results

def main():
    parser = argparse.ArgumentParser(
        description="Validate file formats by magic bytes",
        epilog="Example: python3 magic_byte_validator.py /downloads\npython3 magic_byte_validator.py suspicious.exe"
    )
    parser.add_argument("target", help="File or directory to validate")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    
    results = validate_files(args.target)
    
    # Summary
    if results:
        mismatches = sum(1 for r in results if r['suspicious'])
        print(f"\n[*] Validation Summary")
        print(f"    Total files: {len(results)}")
        print(f"    Format mismatches: {mismatches}")
        
        if mismatches > 0:
            print(f"[!] WARNING: {mismatches} suspicious format mismatch(es) detected")
            return 1
        else:
            print(f"[+] All files have valid formats")
            return 0
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
