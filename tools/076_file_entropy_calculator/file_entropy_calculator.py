#!/usr/bin/env python3
"""
File Entropy Calculator - Calculate Shannon entropy for file or sections.
Calculate overall entropy and sliding 256-byte blocks. ASCII bar chart in terminal.
High entropy (>7.0) = encryption/packing. Classify: <3.0 plain text, 3.0-5.5 compiled,
5.5-7.0 compressed, >7.0 encrypted/packed. Report entropy, classification, high-entropy sections.
"""

import sys
import os
import argparse
import math
import json
from datetime import datetime


class FileEntropyCalculator:
    """Calculate and analyze Shannon entropy of files."""
    
    def __init__(self):
        self.timestamp = datetime.now().isoformat()
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        entropy = 0.0
        for byte_val in range(256):
            freq = data.count(bytes([byte_val]))
            if freq:
                p = freq / len(data)
                entropy -= p * (math.log(p) / math.log(2))
        
        return round(entropy, 4)
    
    def classify_entropy(self, entropy):
        """Classify entropy value."""
        if entropy < 3.0:
            return "Plain Text"
        elif entropy < 5.5:
            return "Compiled/Normal"
        elif entropy < 7.0:
            return "Compressed"
        else:
            return "Encrypted/Packed"
    
    def analyze_file_sections(self, file_path, block_size=256):
        """Analyze entropy of file sections."""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            sections = []
            for i in range(0, len(content), block_size):
                block = content[i:i+block_size]
                entropy = self.calculate_entropy(block)
                sections.append({
                    'offset': i,
                    'size': len(block),
                    'entropy': entropy,
                    'classification': self.classify_entropy(entropy)
                })
            
            return sections
        
        except Exception as e:
            raise Exception(f"Failed to analyze file sections: {e}")
    
    def get_high_entropy_sections(self, sections, threshold=7.0):
        """Get sections with entropy above threshold."""
        return [s for s in sections if s['entropy'] > threshold]
    
    def create_entropy_bar_chart(self, sections, width=60):
        """Create ASCII bar chart of entropy across file."""
        if not sections:
            return ""
        
        chart = []
        max_entropy = max(s['entropy'] for s in sections)
        
        for section in sections[::max(1, len(sections)//40)]:
            bar_width = int((section['entropy'] / max_entropy) * width if max_entropy > 0 else 0)
            bar = "█" * bar_width + "░" * (width - bar_width)
            label = f"0x{section['offset']:06x}"
            chart.append(f"  {label}  {bar}  {section['entropy']:.2f}")
        
        return "\n".join(chart)
    
    def process_file(self, file_path, block_size=256):
        """Process file and calculate entropy."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            overall_entropy = self.calculate_entropy(content)
            sections = self.analyze_file_sections(file_path, block_size)
            high_entropy = self.get_high_entropy_sections(sections)
            
            result = {
                'file': file_path,
                'file_size': os.path.getsize(file_path),
                'timestamp': self.timestamp,
                'block_size': block_size,
                'overall_entropy': overall_entropy,
                'classification': self.classify_entropy(overall_entropy),
                'section_count': len(sections),
                'high_entropy_sections': len(high_entropy),
                'high_entropy_details': high_entropy[:20],
                'sections': sections,
                'min_entropy': round(min(s['entropy'] for s in sections), 4),
                'max_entropy': round(max(s['entropy'] for s in sections), 4),
                'avg_entropy': round(sum(s['entropy'] for s in sections) / len(sections), 4)
            }
            
            return result
        
        except Exception as e:
            raise Exception(f"Failed to process file: {e}")
    
    def print_report(self, result):
        """Print formatted entropy report."""
        print("=" * 90)
        print("FILE ENTROPY ANALYSIS REPORT")
        print("=" * 90)
        print(f"File: {result['file']}")
        print(f"File Size: {result['file_size']} bytes")
        print(f"Timestamp: {result['timestamp']}")
        print(f"Block Size: {result['block_size']} bytes")
        print("")
        
        print("OVERALL ENTROPY")
        print("-" * 90)
        print(f"  Entropy Value: {result['overall_entropy']}")
        print(f"  Classification: {result['classification']}")
        print("")
        
        if result['overall_entropy'] > 7.0:
            print("  ⚠️  HIGH ENTROPY DETECTED - File appears encrypted or packed!")
        elif result['overall_entropy'] > 5.5:
            print("  ℹ️  MODERATE ENTROPY - File may be compressed or obfuscated")
        print("")
        
        print("SECTION ANALYSIS")
        print("-" * 90)
        print(f"  Total Sections: {result['section_count']}")
        print(f"  Min Entropy: {result['min_entropy']}")
        print(f"  Max Entropy: {result['max_entropy']}")
        print(f"  Avg Entropy: {result['avg_entropy']}")
        print(f"  High-Entropy Sections (>7.0): {result['high_entropy_sections']}")
        print("")
        
        if result['high_entropy_sections'] > 0:
            print("HIGH-ENTROPY SECTIONS")
            print("-" * 90)
            for section in result['high_entropy_details'][:10]:
                print(f"  Offset: 0x{section['offset']:06x} | "
                      f"Size: {section['size']:>3} | "
                      f"Entropy: {section['entropy']:.4f} | "
                      f"Type: {section['classification']}")
        
        print("")
        print("ENTROPY DISTRIBUTION")
        print("-" * 90)
        bar_chart = self.create_entropy_bar_chart(result['sections'])
        print(bar_chart)
        print("")
        print("=" * 90)


def main():
    parser = argparse.ArgumentParser(
        description='Calculate Shannon entropy for files and file sections',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 file_entropy_calculator.py -f suspicious_file.exe
  python3 file_entropy_calculator.py -f sample.bin -b 512
  python3 file_entropy_calculator.py -f malware.exe -j entropy_report.json
        """)
    
    parser.add_argument('-f', '--file', required=True, help='File to analyze')
    parser.add_argument('-b', '--block-size', type=int, default=256, help='Block size for section analysis (default: 256)')
    parser.add_argument('-j', '--json', help='Output JSON file')
    
    args = parser.parse_args()
    
    try:
        calculator = FileEntropyCalculator()
        result = calculator.process_file(args.file, args.block_size)
        
        calculator.print_report(result)
        
        if args.json:
            # Limit sections for JSON output size
            output = result.copy()
            output['sections'] = output['sections'][:100]
            
            with open(args.json, 'w') as f:
                json.dump(output, f, indent=2)
            print(f"[+] JSON report written to: {args.json}")
    
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
