#!/usr/bin/env python3
"""
File Format Detector - Detect true file format by magic bytes.
Read first 16 bytes. Match against signatures: PDF, PE, ZIP, GZIP, PNG, JPEG, ELF,
Script, Office XML, RTF. Report: filename, extension, detected format, match status.
Flag mismatches as suspicious.
"""

import sys
import os
import argparse
from pathlib import Path
from datetime import datetime
import json


class FileFormatDetector:
    """Detect true file format by magic byte analysis."""
    
    MAGIC_SIGNATURES = [
        (b'%PDF', 'PDF', '.pdf'),
        (b'MZ', 'PE_Executable', ['.exe', '.dll', '.sys', '.scr']),
        (b'PK\x03\x04', 'ZIP_Archive', ['.zip', '.jar', '.apk', '.docx', '.xlsx']),
        (b'\x1f\x8b', 'GZIP_Compressed', '.gz'),
        (b'\x89PNG\r\n\x1a\n', 'PNG_Image', '.png'),
        (b'\xff\xd8\xff', 'JPEG_Image', '.jpg'),
        (b'GIF8', 'GIF_Image', '.gif'),
        (b'\x7fELF', 'ELF_Executable', ['.elf', '.so', '.bin']),
        (b'{\rtf', 'RTF_Document', '.rtf'),
        (b'BM', 'BMP_Image', '.bmp'),
        (b'\xca\xfe\xba\xbe', 'Mach-O_Executable', '.macho'),
        (b'Rar!', 'RAR_Archive', '.rar'),
        (b'\xfd7zXZ\x00', 'XZ_Compressed', '.xz'),
        (b'\x50\x4b', 'Office_XML', ['.docx', '.xlsx', '.pptx']),
        (b'#!', 'Script', ['.sh', '.py', '.rb']),
    ]
    
    def __init__(self):
        self.timestamp = datetime.now().isoformat()
    
    def read_magic_bytes(self, file_path, num_bytes=16):
        """Read first N bytes of file."""
        try:
            with open(file_path, 'rb') as f:
                return f.read(num_bytes)
        except Exception as e:
            raise Exception(f"Failed to read file: {e}")
    
    def detect_format(self, file_path):
        """Detect file format by magic bytes."""
        try:
            magic = self.read_magic_bytes(file_path)
        except Exception as e:
            return {
                'file': file_path,
                'error': str(e),
                'status': 'error'
            }
        
        filename = os.path.basename(file_path)
        ext = Path(file_path).suffix.lower()
        
        detected_format = None
        detected_ext = None
        magic_matched = False
        
        for sig_bytes, format_name, expected_exts in self.MAGIC_SIGNATURES:
            if magic.startswith(sig_bytes):
                detected_format = format_name
                if isinstance(expected_exts, list):
                    detected_ext = expected_exts[0]
                else:
                    detected_ext = expected_exts
                magic_matched = True
                break
        
        if not detected_format:
            detected_format = "Unknown/Generic"
            detected_ext = "unknown"
        
        # Check for mismatch
        is_suspicious = False
        mismatch_reason = []
        
        if magic_matched:
            if isinstance(self._get_expected_exts_for_format(detected_format), list):
                expected = self._get_expected_exts_for_format(detected_format)
            else:
                expected = [self._get_expected_exts_for_format(detected_format)]
            
            if ext and ext not in expected:
                is_suspicious = True
                mismatch_reason.append(f"Extension mismatch: file has {ext}, detected {expected}")
        
        return {
            'file': file_path,
            'filename': filename,
            'extension': ext or 'none',
            'detected_format': detected_format,
            'expected_extensions': self._get_expected_exts_for_format(detected_format),
            'magic_matched': magic_matched,
            'is_suspicious': is_suspicious,
            'mismatch_reasons': mismatch_reason,
            'magic_bytes': magic[:4].hex(),
            'file_size': os.path.getsize(file_path),
            'status': 'suspicious' if is_suspicious else 'ok'
        }
    
    def _get_expected_exts_for_format(self, format_name):
        """Get expected extensions for detected format."""
        for sig_bytes, fmt, exts in self.MAGIC_SIGNATURES:
            if fmt == format_name:
                return exts if isinstance(exts, list) else [exts]
        return ['unknown']
    
    def process_files(self, path):
        """Process single file or directory."""
        results = []
        
        if os.path.isfile(path):
            results.append(self.detect_format(path))
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        results.append(self.detect_format(file_path))
                    except Exception:
                        pass
        else:
            raise FileNotFoundError(f"Path not found: {path}")
        
        return results
    
    def print_report(self, results):
        """Print formatted detection report."""
        print("=" * 100)
        print("FILE FORMAT DETECTION REPORT")
        print("=" * 100)
        print(f"Timestamp: {self.timestamp}")
        print(f"Total Files: {len(results)}")
        print("")
        
        suspicious_count = sum(1 for r in results if r.get('status') == 'suspicious')
        error_count = sum(1 for r in results if r.get('status') == 'error')
        
        print(f"Suspicious: {suspicious_count}")
        print(f"Errors: {error_count}")
        print(f"Clean: {len(results) - suspicious_count - error_count}")
        print("")
        
        print("┌─ DETAILED RESULTS ──────────────────────────────────────────────────────────────┐")
        
        for result in results:
            if result.get('status') == 'error':
                print(f"│ [!] {result['file']}: {result.get('error')}")
                continue
            
            status_icon = "⚠️ " if result.get('status') == 'suspicious' else "✓ "
            print(f"│ {status_icon} {result['filename']}")
            print(f"│    Path: {result['file']}")
            print(f"│    Extension: {result['extension']}")
            print(f"│    Size: {result['file_size']} bytes")
            print(f"│    Magic: {result['magic_bytes']}")
            print(f"│    Detected Format: {result['detected_format']}")
            print(f"│    Expected Extensions: {', '.join(result.get('expected_extensions', ['unknown']))}")
            
            if result.get('is_suspicious'):
                print(f"│    ⚠️  SUSPICIOUS:")
                for reason in result.get('mismatch_reasons', []):
                    print(f"│       - {reason}")
            
            print("│")
        
        print("└──────────────────────────────────────────────────────────────────────────────────┘")
        
        if suspicious_count > 0:
            print(f"\n[!] Found {suspicious_count} suspicious file(s) with format mismatches!")


def main():
    parser = argparse.ArgumentParser(
        description='Detect true file format by magic bytes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 file_format_detector.py -f sample.exe
  python3 file_format_detector.py -d /path/to/samples
  python3 file_format_detector.py -f file.txt -j results.json
        """)
    
    parser.add_argument('-f', '--file', help='Single file to analyze')
    parser.add_argument('-d', '--directory', help='Directory to scan recursively')
    parser.add_argument('-j', '--json', help='Output JSON file')
    
    args = parser.parse_args()
    
    if not args.file and not args.directory:
        parser.print_help()
        sys.exit(1)
    
    try:
        detector = FileFormatDetector()
        
        if args.file:
            path = args.file
        else:
            path = args.directory
        
        results = detector.process_files(path)
        detector.print_report(results)
        
        if args.json:
            with open(args.json, 'w') as f:
                json.dump({
                    'timestamp': detector.timestamp,
                    'results': results
                }, f, indent=2)
            print(f"[+] JSON report written to: {args.json}")
    
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
