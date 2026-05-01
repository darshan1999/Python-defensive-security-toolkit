#!/usr/bin/env python3
"""
Nested JSON Exporter - Convert flat CSV to nested JSON.

Accepts CSV with nested structure (src_country -> src.country).
Outputs pretty JSON array with metadata.
Metadata includes: timestamp, total records, field list.
"""

import argparse
import csv
import json
from datetime import datetime

class NestedJSONExporter:
    """Converts flat CSV to nested JSON."""
    
    def __init__(self):
        self.records = []
        self.fields = []
    
    def parse_csv(self, csv_file):
        """Parse CSV file."""
        try:
            with open(csv_file, 'r') as f:
                reader = csv.DictReader(f)
                self.fields = reader.fieldnames or []
                
                for row in reader:
                    nested_record = self._flatten_to_nested(row)
                    self.records.append(nested_record)
        except Exception as e:
            print(f"[!] Error reading CSV: {e}", flush=True)
    
    def _flatten_to_nested(self, flat_dict):
        """Convert flat dictionary to nested structure."""
        nested = {}
        
        for key, value in flat_dict.items():
            # Split by underscore to create nesting
            parts = key.split('_', 1)
            
            if len(parts) == 2:
                parent, child = parts
                
                if parent not in nested:
                    nested[parent] = {}
                
                # Handle further nesting
                if '_' in child:
                    subparts = child.split('_', 1)
                    subparent = nested[parent]
                    for part in subparts[:-1]:
                        if part not in subparent:
                            subparent[part] = {}
                        subparent = subparent[part]
                    subparent[subparts[-1]] = value
                else:
                    nested[parent][child] = value
            else:
                nested[key] = value
        
        return nested
    
    def export_json(self, output_file):
        """Export to JSON with metadata."""
        output = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_records': len(self.records),
                'fields': self.fields,
                'nested_format': True
            },
            'records': self.records
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(output, f, indent=2)
            
            print(f"[+] JSON saved to {output_file}")
            print(f"[+] Records: {len(self.records)}, Fields: {len(self.fields)}")
        except Exception as e:
            print(f"[!] Error writing JSON: {e}", flush=True)

def main():
    parser = argparse.ArgumentParser(
        description='Convert flat CSV to nested JSON.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 nested_json_exporter.py --input flat.csv --output nested.json
  python3 nested_json_exporter.py --input data.csv --output output.json
  
CSV structure example:
  src_ip,src_country,dst_ip,dst_country
  10.0.0.1,US,192.168.1.1,GB
  
Becomes:
  {
    "src": {"ip": "10.0.0.1", "country": "US"},
    "dst": {"ip": "192.168.1.1", "country": "GB"}
  }
        """)
    
    parser.add_argument('--input', type=str, required=True, help='Input CSV file')
    parser.add_argument('--output', type=str, required=True, help='Output JSON file')
    
    args = parser.parse_args()
    
    exporter = NestedJSONExporter()
    
    print(f"[*] Parsing {args.input}...", flush=True)
    exporter.parse_csv(args.input)
    
    exporter.export_json(args.output)

if __name__ == "__main__":
    main()
