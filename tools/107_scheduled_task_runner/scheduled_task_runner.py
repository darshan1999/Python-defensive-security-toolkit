#!/usr/bin/env python3
"""Scheduled Task Runner - Executes scheduled tasks with monitoring."""

import sys, subprocess, argparse, json
from datetime import datetime

def run_task(cmd, timeout=30):
    """Execute task with timeout."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
        return {
            'returncode': result.returncode,
            'stdout': result.stdout.decode('utf-8', errors='ignore'),
            'stderr': result.stderr.decode('utf-8', errors='ignore'),
            'status': 'success' if result.returncode == 0 else 'failed'
        }
    except subprocess.TimeoutExpired:
        return {'status': 'timeout', 'error': f'Timeout after {timeout}s'}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}

def main():
    p = argparse.ArgumentParser(description="Run scheduled tasks")
    p.add_argument("command", help="Command to execute")
    p.add_argument("--timeout", type=int, default=30, help="Timeout in seconds")
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    try:
        result = run_task(args.command, args.timeout)
        result['timestamp'] = datetime.now().isoformat()
        
        print(f"[+] Task Execution Report")
        print(f"    Status: {result['status']}")
        print(f"    Return code: {result.get('returncode', 'N/A')}")
        
        if args.output:
            json.dump(result, open(args.output, 'w'), indent=2)
        
        return result.get('returncode', 1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
