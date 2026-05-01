#!/usr/bin/env python3
"""
After-Hours Change Monitor - Detects file modifications outside business hours.
Helps identify compromise attempts occurring during off-peak times.
"""

import sys
import os
import json
import argparse
import hashlib
from datetime import datetime
from pathlib import Path

BUSINESS_HOURS_START = 9
BUSINESS_HOURS_END = 18
BUSINESS_DAYS = {0, 1, 2, 3, 4}  # Monday-Friday

def is_business_hours(timestamp: float) -> tuple:
    """Check if timestamp is within business hours. Returns (is_business, details)."""
    dt = datetime.fromtimestamp(timestamp)
    day_name = dt.strftime("%A")
    is_weekday = dt.weekday() in BUSINESS_DAYS
    is_work_hours = BUSINESS_HOURS_START <= dt.hour < BUSINESS_HOURS_END
    return (is_weekday and is_work_hours, dt, day_name)

def scan_directory(directory: str) -> list:
    """Scan directory for after-hours modifications."""
    suspicious = []
    
    print(f"[*] Scanning {directory} for after-hours modifications...")
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                mtime = os.path.getmtime(filepath)
                is_biz, dt, day_name = is_business_hours(mtime)
                
                if not is_biz:
                    hours_off = abs((dt.hour - BUSINESS_HOURS_START) % 24)
                    suspicious.append({
                        'filepath': filepath,
                        'modified': dt.isoformat(),
                        'day': day_name,
                        'hour': dt.hour,
                        'hours_off': hours_off if dt.hour < BUSINESS_HOURS_START else 24 - dt.hour
                    })
                    print(f"[!] After-hours: {filepath} ({day_name} {dt.strftime('%H:%M:%S')})")
                    
            except Exception as e:
                pass
    
    return suspicious

def main():
    parser = argparse.ArgumentParser(
        description="Detect file modifications outside business hours",
        epilog="Example: python3 after_hours_change_monitor.py /home/user --start 9 --end 18"
    )
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--start", type=int, default=9, help="Business hours start (0-23)")
    parser.add_argument("--end", type=int, default=18, help="Business hours end (0-23)")
    parser.add_argument("--weekdays", default="12345", help="Business days (1=Mon...5=Fri)")
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.directory):
        print(f"Error: {args.directory} not found", file=sys.stderr)
        return 1
    
    try:
        global BUSINESS_HOURS_START, BUSINESS_HOURS_END, BUSINESS_DAYS
        BUSINESS_HOURS_START = args.start
        BUSINESS_HOURS_END = args.end
        BUSINESS_DAYS = set(int(d) - 1 for d in args.weekdays if d.isdigit())
        
        suspicious = scan_directory(args.directory)
        
        print(f"\n[*] After-Hours Modification Report")
        print(f"    Total after-hours changes: {len(suspicious)}")
        
        if suspicious:
            print(f"\n[!] Suspicious After-Hours Activity:")
            for item in sorted(suspicious, key=lambda x: x['modified']):
                print(f"    {item['filepath']}")
                print(f"      Time: {item['modified']} ({item['day']} {item['hour']:02d}:00)")
            return 1
        else:
            print("[+] No after-hours modifications detected")
            return 0
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
