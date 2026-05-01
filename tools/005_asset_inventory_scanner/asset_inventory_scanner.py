#!/usr/bin/env python3
"""Asset Inventory Scanner - Scans network for connected devices."""

import sys, socket, subprocess, argparse, json
from ipaddress import ip_network

def ping_sweep(network_str):
    """Ping sweep to find active hosts."""
    active = []
    try:
        net = ip_network(network_str, strict=False)
        for ip in list(net.hosts())[:50]:
            try:
                result = subprocess.run(f'ping -c 1 -W 1 {ip}', shell=True, 
                                      capture_output=True, timeout=2)
                if result.returncode == 0:
                    active.append(str(ip))
            except:
                pass
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
    return active

def get_hostname(ip):
    """Get hostname for IP."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except:
        return None

def main():
    p = argparse.ArgumentParser(description="Scan network for assets")
    p.add_argument("network", help="Network range (e.g., 192.168.1.0/24)")
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    try:
        print("[*] Scanning network...")
        active_hosts = ping_sweep(args.network)
        
        assets = []
        for ip in active_hosts:
            hostname = get_hostname(ip)
            assets.append({'ip': ip, 'hostname': hostname or 'unknown', 'status': 'active'})
        
        print(f"[+] Asset Inventory Report")
        print(f"    Network: {args.network}")
        print(f"    Active hosts: {len(assets)}")
        
        for a in assets[:10]:
            print(f"    {a['ip']}: {a['hostname']}")
        
        if args.output:
            json.dump(assets, open(args.output, 'w'), indent=2)
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
