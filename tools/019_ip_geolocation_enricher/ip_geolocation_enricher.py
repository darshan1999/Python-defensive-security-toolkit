#!/usr/bin/env python3
"""IP Geolocation Enricher - Enriches IPs with geolocation data."""

import sys, json, argparse

GEO_DB = {
    '1.1.1.1': {'country': 'AU', 'city': 'Sydney', 'asn': 'AS13335'},
    '8.8.8.8': {'country': 'US', 'city': 'Mountain View', 'asn': 'AS15169'},
    '1.0.0.1': {'country': 'AU', 'city': 'Sydney', 'asn': 'AS13335'},
}

PRIVATE_RANGES = ['10.', '172.16.', '172.31.', '192.168.', '127.']

def enrich_ip(ip):
    """Enrich IP with geolocation."""
    if any(ip.startswith(p) for p in PRIVATE_RANGES):
        return {'ip': ip, 'type': 'private', 'geolocated': False}
    
    if ip in GEO_DB:
        return {'ip': ip, 'type': 'public', **GEO_DB[ip], 'geolocated': True}
    
    return {'ip': ip, 'type': 'public', 'geolocated': False}

def main():
    p = argparse.ArgumentParser(description="Enrich IPs with geolocation")
    p.add_argument("ips", nargs='*', help="IP addresses")
    p.add_argument("--input", help="Input file with IPs")
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    try:
        ips = args.ips
        if args.input:
            with open(args.input) as f:
                ips.extend(f.read().strip().split('\n'))
        
        results = [enrich_ip(ip) for ip in ips if ip]
        
        print(f"[+] IP Geolocation Report")
        print(f"    IPs enriched: {len(results)}")
        print(f"    Geolocated: {sum(1 for r in results if r['geolocated'])}")
        
        for r in results[:5]:
            if r['geolocated']:
                print(f"    {r['ip']}: {r['country']}/{r['city']}")
        
        if args.output:
            json.dump(results, open(args.output, 'w'))
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
