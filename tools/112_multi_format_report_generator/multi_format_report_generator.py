#!/usr/bin/env python3
"""Multi Format Report Generator - Generates reports in JSON, CSV, and TXT formats."""

import sys, json, csv, argparse
from datetime import datetime

def gen_json_report(data):
    return json.dumps(data, indent=2)

def gen_csv_report(data):
    if not data or not isinstance(data, list) or not isinstance(data[0], dict):
        return "Invalid data for CSV"
    
    output = []
    keys = data[0].keys()
    output.append(','.join(keys))
    for row in data:
        output.append(','.join(str(row.get(k, '')) for k in keys))
    
    return '\n'.join(output)

def gen_txt_report(data):
    lines = [f"Report Generated: {datetime.now().isoformat()}", "="*60]
    if isinstance(data, list):
        for i, item in enumerate(data, 1):
            lines.append(f"\n[{i}] {json.dumps(item, indent=2)}")
    else:
        lines.append(json.dumps(data, indent=2))
    return '\n'.join(lines)

def main():
    p = argparse.ArgumentParser(description="Generate reports in multiple formats")
    p.add_argument("data", help="JSON input data")
    p.add_argument("--format", choices=['json', 'csv', 'txt', 'all'], default='json')
    p.add_argument("--output", help="Output file/prefix")
    args = p.parse_args()
    
    try:
        data = json.loads(args.data)
        
        formatters = {'json': gen_json_report, 'csv': gen_csv_report, 'txt': gen_txt_report}
        
        if args.format == 'all':
            for fmt in ['json', 'csv', 'txt']:
                output = formatters[fmt](data)
                if args.output:
                    with open(f'{args.output}.{fmt}', 'w') as f:
                        f.write(output)
                else:
                    print(output)
        else:
            output = formatters[args.format](data)
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(output)
            else:
                print(output)
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
