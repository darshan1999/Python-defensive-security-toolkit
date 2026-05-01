#!/usr/bin/env python3
"""URL Extractor - Extracts URLs from files and text."""

import sys, re, argparse, json

URL_PATTERN = r'https?://[^\s<>"{}|\\^`\[\]]+'

def extract_urls(text):
    """Extract URLs from text."""
    return list(set(re.findall(URL_PATTERN, text)))

def categorize_urls(urls):
    """Categorize URLs by domain."""
    categories = {}
    for url in urls:
        domain = url.split('/')[2] if len(url.split('/')) > 2 else 'unknown'
        if domain not in categories:
            categories[domain] = []
        categories[domain].append(url)
    return categories

def main():
    p = argparse.ArgumentParser(description="Extract URLs from files")
    p.add_argument("input", nargs='?', default='-', help="File or stdin")
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    try:
        if args.input == '-':
            text = sys.stdin.read()
        else:
            with open(args.input, 'rb') as f:
                text = f.read().decode('utf-8', errors='ignore')
        
        urls = extract_urls(text)
        categories = categorize_urls(urls)
        
        print(f"[+] URL Extraction Report")
        print(f"    Total URLs: {len(urls)}")
        print(f"    Unique domains: {len(categories)}")
        
        for domain, domain_urls in list(categories.items())[:5]:
            print(f"    {domain}: {len(domain_urls)}")
        
        if args.output:
            json.dump(urls, open(args.output, 'w'))
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
