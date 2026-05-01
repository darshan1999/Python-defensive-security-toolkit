#!/usr/bin/env python3
"""Timestamp Normalizer - Converts timestamps to ISO 8601 format."""

import sys, argparse, json
from datetime import datetime

FORMATS = [
    '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%d/%m/%Y %H:%M:%S',
    '%m/%d/%Y %H:%M:%S', '%Y%m%d %H:%M:%S', '%d-%m-%Y %H:%M:%S'
]

def normalize(ts_str):
    for fmt in FORMATS:
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.isoformat(), 'success'
        except:
            pass
    try:
        dt = datetime.fromtimestamp(float(ts_str))
        return dt.isoformat(), 'unix'
    except:
        return None, 'failed'

def main():
    p = argparse.ArgumentParser(description="Normalize timestamps")
    p.add_argument("timestamp", help="Timestamp to normalize")
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    try:
        result, fmt = normalize(args.timestamp)
        
        if result:
            print(f"[+] Timestamp normalized: {result}")
            if args.output:
                json.dump({'original': args.timestamp, 'normalized': result, 'format': fmt},
                         open(args.output, 'w'))
            return 0
        else:
            print(f"Error: Could not parse timestamp", file=sys.stderr)
            return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
