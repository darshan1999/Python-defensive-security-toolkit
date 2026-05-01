#!/usr/bin/env python3
"""
Domain Extractor - Extracts domain names from files or text input.
Categorizes domains and detects typosquatting patterns for threat analysis.
"""

import sys
import re
import argparse
from pathlib import Path
from collections import defaultdict

SUSPICIOUS_TLDS = {'.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.info'}
COMMON_CDNS = {'cloudflare.com', 'akamai.com', 'fastly.com', 'amazonaws.com', 'azurewebsites.net'}
INTERNAL_DOMAINS = {'.local', '.internal', '.corp', '.lan', '.dev'}

def extract_domains(text: str) -> set:
    """Extract FQDNs from text."""
    # Regex for domain names
    domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
    domains = set()
    
    for match in re.finditer(domain_pattern, text):
        domain = match.group(0).lower()
        # Filter out version numbers that look like domains (1.2.3.4)
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            domains.add(domain)
    
    return domains

def categorize_domain(domain: str) -> str:
    """Categorize domain."""
    if any(domain.endswith(tld) for tld in INTERNAL_DOMAINS):
        return 'INTERNAL'
    elif any(cdn in domain for cdn in COMMON_CDNS):
        return 'CDN'
    elif any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        return 'SUSPICIOUS_TLD'
    else:
        return 'EXTERNAL'

def detect_typosquatting(domains: set) -> dict:
    """Detect potential typosquatting of common domains."""
    typosquats = {}
    common_domains = {'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'paypal.com', 'facebook.com'}
    
    for domain in domains:
        for common in common_domains:
            # Simple typosquatting detection
            if domain != common and common.replace('a', 'a|0|@').replace('e', 'e|3') in domain:
                typosquats[domain] = f"Possible typosquatting of {common}"
    
    return typosquats

def main():
    parser = argparse.ArgumentParser(
        description="Extract domain names from files or text",
        epilog="Examples:\n  python3 domain_extractor.py data.txt\n  echo 'Visit google.com or evil.xyz' | python3 domain_extractor.py -"
    )
    parser.add_argument("input", nargs='?', default='-', help="Input file or - for stdin")
    parser.add_argument("--output", help="Output file (JSON)")
    parser.add_argument("--deduplicate", action="store_true", help="Remove duplicates")
    
    args = parser.parse_args()
    
    try:
        # Read input
        if args.input == '-':
            text = sys.stdin.read()
        else:
            if not Path(args.input).exists():
                print(f"Error: {args.input} not found", file=sys.stderr)
                return 1
            with open(args.input) as f:
                text = f.read()
        
        # Extract domains
        domains = extract_domains(text)
        
        # Categorize
        categorized = defaultdict(list)
        for domain in domains:
            category = categorize_domain(domain)
            categorized[category].append(domain)
        
        # Detect typosquatting
        typosquats = detect_typosquatting(domains)
        
        # Output
        print(f"[+] Domain Extraction Report")
        print(f"    Total domains: {len(domains)}")
        
        for category in ['INTERNAL', 'EXTERNAL', 'CDN', 'SUSPICIOUS_TLD']:
            if categorized[category]:
                print(f"\n[{category}] ({len(categorized[category])})")
                for domain in sorted(categorized[category])[:20]:
                    print(f"    {domain}")
                if len(categorized[category]) > 20:
                    print(f"    ... and {len(categorized[category]) - 20} more")
        
        if typosquats:
            print(f"\n[!] TYPOSQUATTING DETECTED:")
            for domain, reason in typosquats.items():
                print(f"    {domain} - {reason}")
        
        return 0 if not typosquats else 1
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
