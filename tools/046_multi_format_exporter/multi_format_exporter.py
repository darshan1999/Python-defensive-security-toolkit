#!/usr/bin/env python3
"""
Multi-Format Exporter - Exports security data to multiple formats (CSV, JSON, TXT, HTML).
Converts unified JSON input to analyst-friendly output formats.
"""

import sys
import json
import csv
import argparse
from pathlib import Path
from datetime import datetime

def export_csv(data: list, output_file: str, fields: list = None):
    """Export data to CSV format."""
    if not data:
        print("Error: No data to export", file=sys.stderr)
        return False
    
    if fields is None:
        fields = list(data[0].keys()) if isinstance(data[0], dict) else []
    
    try:
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for row in data:
                writer.writerow({k: row.get(k, '') for k in fields})
        print(f"[+] Exported to CSV: {output_file}")
        return True
    except Exception as e:
        print(f"Error exporting CSV: {e}", file=sys.stderr)
        return False

def export_json(data: list, output_file: str):
    """Export data to JSON format."""
    try:
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        print(f"[+] Exported to JSON: {output_file}")
        return True
    except Exception as e:
        print(f"Error exporting JSON: {e}", file=sys.stderr)
        return False

def export_txt(data: list, output_file: str):
    """Export data to formatted TXT with ASCII borders."""
    try:
        with open(output_file, 'w') as f:
            if not data:
                f.write("No data to export\n")
                return True
            
            keys = list(data[0].keys()) if isinstance(data[0], dict) else []
            col_widths = {k: max(len(str(k)), max(len(str(row.get(k, ''))) for row in data)) for k in keys}
            
            # Header
            header = " | ".join(f"{k:^{col_widths[k]}}" for k in keys)
            border = "-" * len(header)
            f.write(border + "\n")
            f.write(header + "\n")
            f.write(border + "\n")
            
            # Rows
            for row in data:
                row_str = " | ".join(f"{str(row.get(k, '')):^{col_widths[k]}}" for k in keys)
                f.write(row_str + "\n")
            
            f.write(border + "\n")
        print(f"[+] Exported to TXT: {output_file}")
        return True
    except Exception as e:
        print(f"Error exporting TXT: {e}", file=sys.stderr)
        return False

def export_html(data: list, output_file: str):
    """Export data to HTML with severity color coding."""
    try:
        severity_colors = {
            'CRITICAL': '#ff4444',
            'HIGH': '#ff8844',
            'MEDIUM': '#ffaa44',
            'LOW': '#44ff44',
            'INFO': '#4488ff'
        }
        
        html = """<html>
<head>
    <title>Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #333; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Security Analysis Report</h1>
    <p>Generated: """ + datetime.now().isoformat() + """</p>
    <table>
"""
        
        if data:
            keys = list(data[0].keys()) if isinstance(data[0], dict) else []
            html += "        <tr>\n"
            for key in keys:
                html += f"            <th>{key}</th>\n"
            html += "        </tr>\n"
            
            for row in data:
                severity = row.get('severity', 'INFO')
                bg_color = severity_colors.get(severity, '#ffffff')
                html += f'        <tr style="background-color: {bg_color};">\n'
                for key in keys:
                    value = row.get(key, '')
                    html += f"            <td>{value}</td>\n"
                html += "        </tr>\n"
        
        html += """    </table>
</body>
</html>"""
        
        with open(output_file, 'w') as f:
            f.write(html)
        print(f"[+] Exported to HTML: {output_file}")
        return True
    except Exception as e:
        print(f"Error exporting HTML: {e}", file=sys.stderr)
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Export security data to multiple formats",
        epilog="Example: python3 multi_format_exporter.py events.json --format csv --output report.csv"
    )
    parser.add_argument("input", help="Input JSON file")
    parser.add_argument("--format", choices=['csv', 'json', 'txt', 'html', 'all'], default='json',
                       help="Output format")
    parser.add_argument("--output", help="Output file (without extension for --format all)")
    parser.add_argument("--fields", help="Comma-separated fields to include")
    
    args = parser.parse_args()
    
    # Load JSON data
    try:
        with open(args.input) as f:
            data = json.load(f)
            if not isinstance(data, list):
                data = [data]
    except Exception as e:
        print(f"Error loading JSON: {e}", file=sys.stderr)
        return 1
    
    # Parse fields
    fields = None
    if args.fields:
        fields = [f.strip() for f in args.fields.split(',')]
    
    # Export
    success = False
    if args.format == 'csv':
        output = args.output or 'output.csv'
        success = export_csv(data, output, fields)
    elif args.format == 'json':
        output = args.output or 'output.json'
        success = export_json(data, output)
    elif args.format == 'txt':
        output = args.output or 'output.txt'
        success = export_txt(data, output)
    elif args.format == 'html':
        output = args.output or 'output.html'
        success = export_html(data, output)
    elif args.format == 'all':
        base = args.output or 'output'
        success = (export_csv(data, f"{base}.csv", fields) and
                  export_json(data, f"{base}.json") and
                  export_txt(data, f"{base}.txt") and
                  export_html(data, f"{base}.html"))
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
