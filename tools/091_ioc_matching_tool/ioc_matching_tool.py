#!/usr/bin/env python3
"""
IOC Matching Tool - Matches extracted IOCs against threat intelligence databases.
Provides context and correlation scoring for fast triage.
"""

import sys
import json
import argparse
import re
from collections import Counter

def load_threat_feeds(filepath: str) -> dict:
    """Load threat intelligence feeds."""
    try:
        with open(filepath) as f:
            feeds = json.load(f)
            return feeds if isinstance(feeds, dict) else {'iocs': feeds}
    except:
        return {'iocs': []}

def normalize_ioc(ioc: str, ioc_type: str) -> str:
    """Normalize IOC format."""
    if ioc_type in ['domain', 'fqdn']:
        return ioc.lower().strip()
    elif ioc_type in ['hash', 'md5', 'sha1', 'sha256']:
        return ioc.lower().strip()
    elif ioc_type == 'ip':
        return ioc.strip()
    return ioc.strip()

def calculate_match_score(ioc: str, feed_iocs: list) -> dict:
    """Calculate match confidence score."""
    matches = []
    for feed_ioc in feed_iocs:
        if isinstance(feed_ioc, dict):
            value = feed_ioc.get('value', str(feed_ioc)).lower()
            confidence = feed_ioc.get('confidence', 100)
        else:
            value = str(feed_ioc).lower()
            confidence = 100
        
        if ioc.lower() == value:
            matches.append({
                'value': value,
                'confidence': confidence,
                'tags': feed_ioc.get('tags', []) if isinstance(feed_ioc, dict) else []
            })
    
    return {
        'matched': len(matches) > 0,
        'count': len(matches),
        'avg_confidence': sum(m['confidence'] for m in matches) / len(matches) if matches else 0,
        'details': matches
    }

def correlate_iocs(iocs_list: list) -> dict:
    """Find correlations between IOCs."""
    correlations = {}
    
    # Check for related domains
    domains = [ioc for ioc in iocs_list if '@' not in ioc and '.' in ioc]
    domain_bases = ['.'.join(d.split('.')[-2:]) for d in domains]
    base_counts = Counter(domain_bases)
    
    for base, count in base_counts.items():
        if count > 1:
            correlations[base] = {'type': 'shared_domain', 'count': count}
    
    return correlations

def main():
    parser = argparse.ArgumentParser(
        description="Match IOCs against threat intelligence feeds",
        epilog="Example: python3 ioc_matching_tool.py iocs.json --feeds threats.json"
    )
    parser.add_argument("input", help="JSON file with IOCs to match")
    parser.add_argument("--feeds", required=True, help="Threat intelligence feed JSON")
    parser.add_argument("--min-confidence", type=int, default=70, help="Minimum confidence threshold")
    
    args = parser.parse_args()
    
    try:
        with open(args.input) as f:
            iocs = json.load(f)
            if isinstance(iocs, dict):
                iocs = iocs.get('iocs', [])
            elif not isinstance(iocs, list):
                iocs = [iocs]
        
        feeds = load_threat_feeds(args.feeds)
        
        results = {
            'total_iocs': len(iocs),
            'matches': [],
            'correlations': correlate_iocs(iocs)
        }
        
        feed_iocs = feeds.get('iocs', [])
        
        for ioc in iocs:
            ioc_value = ioc if isinstance(ioc, str) else ioc.get('value', '')
            match_result = calculate_match_score(ioc_value, feed_iocs)
            
            if match_result['matched'] and match_result['avg_confidence'] >= args.min_confidence:
                results['matches'].append({
                    'ioc': ioc_value,
                    'confidence': match_result['avg_confidence'],
                    'sources': match_result['count']
                })
        
        print(f"[+] IOC Matching Report")
        print(f"    Total IOCs analyzed: {results['total_iocs']}")
        print(f"    Matches found: {len(results['matches'])}")
        
        if results['matches']:
            print(f"\n[!] HIGH-CONFIDENCE MATCHES:")
            for match in sorted(results['matches'], key=lambda x: x['confidence'], reverse=True)[:10]:
                print(f"    {match['ioc']} (confidence: {match['confidence']:.0f}%)")
        
        if results['correlations']:
            print(f"\n[*] Correlations: {len(results['correlations'])}")
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
