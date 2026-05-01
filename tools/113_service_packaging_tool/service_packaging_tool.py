#!/usr/bin/env python3
"""Service Packaging Tool - Packages tools as services/daemons."""

import sys, json, argparse, os
from datetime import datetime

def package_service(name, cmd, description=''):
    """Package tool as service."""
    return {
        'name': name,
        'description': description or f'Service for {name}',
        'command': cmd,
        'created': datetime.now().isoformat(),
        'type': 'service',
        'status': 'packaged'
    }

def generate_systemd_unit(service):
    """Generate systemd unit file."""
    unit = f"""[Unit]
Description={service['description']}
After=network.target

[Service]
Type=simple
ExecStart={service['command']}
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""
    return unit

def main():
    p = argparse.ArgumentParser(description="Package tools as services")
    p.add_argument("name", help="Service name")
    p.add_argument("command", help="Command to execute")
    p.add_argument("--description", help="Service description")
    p.add_argument("--output", help="Output JSON")
    p.add_argument("--systemd", help="Generate systemd unit file")
    args = p.parse_args()
    
    try:
        service = package_service(args.name, args.command, args.description)
        
        print(f"[+] Service Packaging Report")
        print(f"    Name: {service['name']}")
        print(f"    Status: {service['status']}")
        
        if args.output:
            json.dump(service, open(args.output, 'w'), indent=2)
        
        if args.systemd:
            unit = generate_systemd_unit(service)
            with open(args.systemd, 'w') as f:
                f.write(unit)
            print(f"    Systemd unit: {args.systemd}")
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
