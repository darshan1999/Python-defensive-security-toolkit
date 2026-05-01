#!/usr/bin/env python3
"""
SSH Login Parser - Parses auth.log for SSH login events and generates security analysis.
Extracts failed attempts, successful logins, and anomalies from syslog.
"""

import sys
import re
import argparse
from datetime import datetime
from collections import defaultdict

def parse_auth_log(log_file: str) -> dict:
    """Parse auth.log for SSH events."""
    results = {
        'total_events': 0,
        'successful_logins': [],
        'failed_logins': [],
        'invalid_users': [],
        'events_by_ip': defaultdict(int),
        'failed_by_ip': defaultdict(int),
        'users_attempted': set()
    }
    
    patterns = {
        'failed': r'Failed password for (\S+) from ([\d.]+) port (\d+)',
        'invalid': r'Invalid user (\S+) from ([\d.]+) port (\d+)',
        'accepted_pwd': r'Accepted password for (\S+) from ([\d.]+) port (\d+)',
        'accepted_key': r'Accepted publickey for (\S+) from ([\d.]+) port (\d+)'
    }
    
    try:
        with open(log_file) as f:
            for line in f:
                results['total_events'] += 1
                
                # Check failed password
                match = re.search(patterns['failed'], line)
                if match:
                    user, ip, port = match.groups()
                    results['failed_logins'].append({'user': user, 'ip': ip, 'port': port, 'line': line})
                    results['failed_by_ip'][ip] += 1
                    results['users_attempted'].add(user)
                    results['events_by_ip'][ip] += 1
                    continue
                
                # Check invalid user
                match = re.search(patterns['invalid'], line)
                if match:
                    user, ip, port = match.groups()
                    results['invalid_users'].append({'user': user, 'ip': ip, 'port': port, 'line': line})
                    results['failed_by_ip'][ip] += 1
                    results['users_attempted'].add(user)
                    results['events_by_ip'][ip] += 1
                    continue
                
                # Check accepted password
                match = re.search(patterns['accepted_pwd'], line)
                if match:
                    user, ip, port = match.groups()
                    results['successful_logins'].append({'user': user, 'ip': ip, 'port': port, 'auth': 'password'})
                    results['events_by_ip'][ip] += 1
                    continue
                
                # Check accepted publickey
                match = re.search(patterns['accepted_key'], line)
                if match:
                    user, ip, port = match.groups()
                    results['successful_logins'].append({'user': user, 'ip': ip, 'port': port, 'auth': 'publickey'})
                    results['events_by_ip'][ip] += 1
    
    except FileNotFoundError:
        print(f"Error: {log_file} not found", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error parsing log: {e}", file=sys.stderr)
        return None
    
    return results

def main():
    parser = argparse.ArgumentParser(
        description="Parse auth.log for SSH login events",
        epilog="Example: python3 ssh_login_parser.py /var/log/auth.log"
    )
    parser.add_argument("logfile", help="Path to auth.log or syslog")
    parser.add_argument("--top", type=int, default=10, help="Show top N IPs")
    
    args = parser.parse_args()
    
    results = parse_auth_log(args.logfile)
    if not results:
        return 1
    
    print(f"[*] SSH Login Analysis Report")
    print(f"    Total events: {results['total_events']}")
    print(f"    Successful logins: {len(results['successful_logins'])}")
    print(f"    Failed attempts: {len(results['failed_logins'])}")
    print(f"    Invalid user attempts: {len(results['invalid_users'])}")
    print(f"    Unique users targeted: {len(results['users_attempted'])}")
    print(f"    Unique source IPs: {len(results['events_by_ip'])}")
    
    print(f"\n[*] Top {args.top} Most Active IPs:")
    for ip, count in sorted(results['events_by_ip'].items(), key=lambda x: x[1], reverse=True)[:args.top]:
        failed = results['failed_by_ip'][ip]
        status = "⚠️  HIGH RISK" if failed > 10 else "⚠️  MEDIUM" if failed > 5 else "✓ LOW"
        print(f"    {ip:15s} - {count:4d} events ({failed} failed) {status}")
    
    if results['failed_logins']:
        print(f"\n[!] Top Failed Attempts:")
        by_ip = defaultdict(int)
        for attempt in results['failed_logins']:
            by_ip[attempt['ip']] += 1
        
        for ip, count in sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"    {ip:15s} - {count} failed attempts")
    
    if results['invalid_users']:
        print(f"\n[!] Invalid User Attempts: {len(results['invalid_users'])}")
        unique_users = set(item['user'] for item in results['invalid_users'])
        for user in list(unique_users)[:10]:
            count = sum(1 for item in results['invalid_users'] if item['user'] == user)
            print(f"    '{user}' - {count} attempts")
    
    return 1 if results['failed_logins'] else 0

if __name__ == "__main__":
    sys.exit(main())
