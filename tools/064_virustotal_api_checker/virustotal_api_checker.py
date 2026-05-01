#!/usr/bin/env python3
"""
VirusTotal API Checker - Check file hash against VirusTotal API v3.
Accepts SHA256 hash and API key. Queries files endpoint. Parses response for
detections, engines, vendors, threat category. Outputs formatted report for analysts.
Uses urllib.request (standard library only).
"""

import sys
import os
import json
import argparse
import urllib.request
import urllib.error
from datetime import datetime


class VirustotalApiChecker:
    """Query VirusTotal API v3 for file analysis results."""
    
    VT_BASE_URL = "https://www.virustotal.com/api/v3/files"
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.session_timestamp = datetime.now().isoformat()
    
    def query_file_hash(self, sha256_hash):
        """Query VirusTotal API for SHA256 hash analysis."""
        if not self._validate_sha256(sha256_hash):
            raise ValueError(f"Invalid SHA256 hash: {sha256_hash}")
        
        url = f"{self.VT_BASE_URL}/{sha256_hash}"
        headers = {"x-apikey": self.api_key}
        
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    return data.get('data', {})
                else:
                    raise Exception(f"API returned status {response.status}")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise Exception(f"HTTP Error {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            raise Exception(f"URL Error: {e.reason}")
        except Exception as e:
            raise Exception(f"Failed to query VirusTotal: {e}")
    
    def _validate_sha256(self, hash_val):
        """Validate SHA256 format."""
        return bool(hash_val) and len(hash_val) == 64 and all(c in '0123456789abcdefABCDEF' for c in hash_val)
    
    def parse_analysis_results(self, file_data):
        """Parse and extract analysis results from API response."""
        if not file_data:
            return None
        
        analysis_stats = file_data.get('attributes', {}).get('last_analysis_stats', {})
        analysis_results = file_data.get('attributes', {}).get('last_analysis_results', {})
        
        detections = {
            'total': analysis_stats.get('total', 0),
            'malicious': analysis_stats.get('malicious', 0),
            'suspicious': analysis_stats.get('suspicious', 0),
            'undetected': analysis_stats.get('undetected', 0),
            'type_unsupported': analysis_stats.get('type_unsupported', 0),
        }
        
        top_vendors = self._extract_top_vendors(analysis_results)
        category = file_data.get('attributes', {}).get('category', 'unknown')
        threat_names = self._extract_threat_names(analysis_results)
        
        return {
            'detections': detections,
            'top_vendors': top_vendors,
            'category': category,
            'threat_names': threat_names,
            'last_analysis_date': file_data.get('attributes', {}).get('last_analysis_date'),
        }
    
    def _extract_top_vendors(self, analysis_results, limit=5):
        """Extract top detection vendors (Microsoft, Kaspersky, Symantec, etc)."""
        priority_vendors = ['Microsoft', 'Kaspersky', 'Symantec', 'McAfee', 'Fortinet',
                            'Avast', 'AVG', 'Malwarebytes', 'Trend Micro', 'Norton']
        
        detections = {}
        for vendor, result in analysis_results.items():
            if result.get('category') in ('malicious', 'suspicious'):
                detections[vendor] = result.get('engine_name', vendor)
        
        prioritized = []
        for vendor in priority_vendors:
            for engine, name in detections.items():
                if vendor.lower() in engine.lower():
                    prioritized.append((engine, name))
                    break
        
        for engine, name in detections.items():
            if (engine, name) not in prioritized:
                prioritized.append((engine, name))
        
        return prioritized[:limit]
    
    def _extract_threat_names(self, analysis_results):
        """Extract unique threat names from analysis results."""
        threat_names = set()
        for result in analysis_results.values():
            if result.get('category') == 'malicious' and result.get('result'):
                threat_names.add(result['result'])
        return list(threat_names)[:5]
    
    def generate_report(self, sha256_hash, analysis_data):
        """Generate formatted report suitable for analysts."""
        report = []
        report.append("=" * 70)
        report.append("VIRUSTOTAL FILE ANALYSIS REPORT")
        report.append("=" * 70)
        report.append(f"Timestamp: {self.session_timestamp}")
        report.append(f"SHA256: {sha256_hash}")
        report.append("")
        
        if not analysis_data:
            report.append("[-] File not found in VirusTotal database")
            return "\n".join(report)
        
        detections = analysis_data['detections']
        report.append("DETECTION SUMMARY")
        report.append("-" * 70)
        report.append(f"  Total Engines: {detections['total']}")
        report.append(f"  Malicious: {detections['malicious']}")
        report.append(f"  Suspicious: {detections['suspicious']}")
        report.append(f"  Undetected: {detections['undetected']}")
        report.append(f"  Type Unsupported: {detections['type_unsupported']}")
        report.append("")
        
        if detections['malicious'] > 0 or detections['suspicious'] > 0:
            report.append("THREAT CATEGORY")
            report.append("-" * 70)
            report.append(f"  Category: {analysis_data['category']}")
            report.append("")
            
            if analysis_data['threat_names']:
                report.append("IDENTIFIED THREAT NAMES")
                report.append("-" * 70)
                for i, threat in enumerate(analysis_data['threat_names'], 1):
                    report.append(f"  {i}. {threat}")
                report.append("")
            
            if analysis_data['top_vendors']:
                report.append("TOP VENDOR DETECTIONS")
                report.append("-" * 70)
                for i, (vendor, name) in enumerate(analysis_data['top_vendors'], 1):
                    report.append(f"  {i}. {vendor}: {name}")
                report.append("")
        
        report.append("VERDICT")
        report.append("-" * 70)
        if detections['malicious'] >= 5:
            report.append("  ⚠️  MALICIOUS - High confidence threat detected")
        elif detections['malicious'] >= 1:
            report.append("  ⚠️  MALICIOUS - Threat detected by multiple vendors")
        elif detections['suspicious'] >= 3:
            report.append("  ⚠️  SUSPICIOUS - Potentially malicious behavior")
        else:
            report.append("  ✓ CLEAN/UNKNOWN - No significant detections")
        
        report.append("=" * 70)
        return "\n".join(report)


def main():
    parser = argparse.ArgumentParser(
        description='Check file hash against VirusTotal API v3',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 virustotal_api_checker.py -k YOUR_API_KEY -H e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  export VT_API_KEY='YOUR_API_KEY'
  python3 virustotal_api_checker.py -H e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        """)
    
    parser.add_argument('-H', '--hash', required=True, help='SHA256 hash to check')
    parser.add_argument('-k', '--api-key', help='VirusTotal API key (or set VT_API_KEY env var)')
    
    args = parser.parse_args()
    
    api_key = args.api_key or os.environ.get('VT_API_KEY')
    if not api_key:
        print("[-] Error: API key not provided. Set VT_API_KEY env var or use -k flag", file=sys.stderr)
        sys.exit(1)
    
    try:
        checker = VirustotalApiChecker(api_key)
        file_data = checker.query_file_hash(args.hash)
        analysis_data = checker.parse_analysis_results(file_data)
        report = checker.generate_report(args.hash, analysis_data)
        print(report)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
