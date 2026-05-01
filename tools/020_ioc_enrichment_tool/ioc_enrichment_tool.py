#!/usr/bin/env python3
"""IOC Enrichment Tool - Enriches IOCs with threat intelligence."""

import sys, json, argparse

def enrich_ioc(ioc, ioc_type):
    """Enrich IOC with context."""
    enrichment = {'ioc': ioc, 'type': ioc_type, 'enriched': False}
    
    if ioc_type == 'domain':
        if 'malware' in ioc.lower():
            enrichment['threat'] = 'malware_distribution'
            enrichment['enriched'] = True
        elif 'phish' in ioc.lower():
            enrichment['threat'] = 'phishing'
            enrichment['enriched'] = True
    
    elif ioc_type == 'hash':
        enrichment['threat'] = 'potentially_malicious'
        enrichment['enriched'] = True
    
    return enrichment

def main():
    p = argparse.ArgumentParser(description="Enrich IOCs with threat intel")
    p.add_argument("ioc", help="IOC value")
    p.add_argument("--type", choices=['domain', 'hash', 'ip', 'url'], default='domain')
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    try:
        result = enrich_ioc(args.ioc, args.type)
        
        print(f"[+] IOC Enrichment Report")
        print(f"    IOC: {args.ioc}")
        print(f"    Type: {args.type}")
        print(f"    Enriched: {result['enriched']}")
        
        if 'threat' in result:
            print(f"    Threat: {result['threat']}")
        
        if args.output:
            json.dump(result, open(args.output, 'w'))
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
