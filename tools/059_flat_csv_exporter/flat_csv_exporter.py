#!/usr/bin/env python3
"""
Flat CSV Exporter - Convert JSON array to flat CSV.

Accepts JSON file and optional field selection.
Flattens nested structures (geo.country -> geo_country).
Handles missing fields gracefully.
Supports --sort by field.
"""

import argparse
import csv
import json

class FlatCSVExporter:
    """Exports JSON to flattened CSV."""
    
    def __init__(self, json_file):
        self.data = self._load_json(json_file)
        self.flattened = []
    
    def _load_json(self, filepath):
        """Load JSON data."""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                return data if isinstance(data, list) else [data]
        except Exception as e:
            print(f"[!] Error loading JSON: {e}", flush=True)
            return []
    
    def _flatten_dict(self, obj, parent_key=''):
        """Recursively flatten nested dictionary."""
        items = []
        
        for k, v in obj.items():
            new_key = f"{parent_key}_{k}" if parent_key else k
            
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key).items())
            elif isinstance(v, list):
                items.append((new_key, ','.join(str(x) for x in v)))
            else:
                items.append((new_key, v))
        
        return dict(items)
    
    def flatten(self, fields=None):
        """Flatten all records."""
        all_keys = set()
        
        # First pass: collect all keys
        for record in self.data:
            if isinstance(record, dict):
                flat_record = self._flatten_dict(record)
                self.flattened.append(flat_record)
                all_keys.update(flat_record.keys())
        
        # Filter fields if specified
        if fields:
            all_keys = all_keys.intersection(set(fields))
        
        self.all_keys = sorted(all_keys)
        
        # Ensure all records have all keys
        for record in self.flattened:
            for key in self.all_keys:
                if key not in record:
                    record[key] = None
    
    def sort_by_field(self, field, reverse=False):
        """Sort records by field."""
        try:
            self.flattened.sort(
                key=lambda x: x.get(field, ''),
                reverse=reverse
            )
        except Exception as e:
            print(f"[!] Cannot sort by {field}: {e}", flush=True)
    
    def export_csv(self, output_file):
        """Export to CSV."""
        if not self.flattened or not self.all_keys:
            print("[!] No data to export", flush=True)
            return
        
        try:
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.all_keys)
                writer.writeheader()
                writer.writerows(self.flattened)
            
            print(f"[+] CSV saved to {output_file}")
            print(f"[+] Records: {len(self.flattened)}, Fields: {len(self.all_keys)}")
        except Exception as e:
            print(f"[!] Error writing CSV: {e}", flush=True)

def main():
    parser = argparse.ArgumentParser(
        description='Convert JSON array to flat CSV.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 flat_csv_exporter.py --input data.json --output flat.csv
  python3 flat_csv_exporter.py --input alerts.json --output report.csv --sort severity
  python3 flat_csv_exporter.py --input data.json --output out.csv --fields ip,timestamp,severity
        """)
    
    parser.add_argument('--input', type=str, required=True, help='Input JSON file')
    parser.add_argument('--output', type=str, required=True, help='Output CSV file')
    parser.add_argument('--fields', type=str, help='Comma-separated field list to include')
    parser.add_argument('--sort', type=str, help='Sort by field')
    
    args = parser.parse_args()
    
    exporter = FlatCSVExporter(args.input)
    
    fields = args.fields.split(',') if args.fields else None
    exporter.flatten(fields=fields)
    
    if args.sort:
        exporter.sort_by_field(args.sort)
    
    exporter.export_csv(args.output)

if __name__ == "__main__":
    main()
