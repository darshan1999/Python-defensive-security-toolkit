#!/usr/bin/env python3
"""
VirusTotal Bulk Scanner - Scan multiple hashes against VirusTotal in bulk.
Accept text file with SHA256 hashes (one per line) and API key. Query VT API per hash
with 15s delay (rate limit). Show progress. For each: detection ratio, verdict, threat name.
Write full results to JSON. Write high-risk (>3 engines) to separate alert file.
"""

import sys
import os
import json
import argparse
import urllib.request
import urllib.error
import time
from datetime import datetime
from pathlib import Path


class VirustotalBulkScanner:
    """Bulk scan multiple file hashes against VirusTotal API v3."""
    
    VT_BASE_URL = "https://www.virustotal.com/api/v3/files"
    RATE_LIMIT_DELAY = 15  # seconds between requests
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.session_timestamp = datetime.now().isoformat()
        self.results = []
        self.alerts = []
    
    def _validate_sha256(self, hash_val):
        """Validate SHA256 format."""
        return bool(hash_val) and len(hash_val) == 64 and all(c in '0123456789abcdefABCDEF' for c in hash_val)
    
    def query_file_hash(self, sha256_hash):
        """Query single hash against VT API."""
        if not self._validate_sha256(sha256_hash):
            return None
        
        url = f"{self.VT_BASE_URL}/{sha256_hash}"
        headers = {"x-apikey": self.api_key}
        
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    return json.loads(response.read().decode('utf-8')).get('data', {})
                return None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            return None
        except Exception:
            return None
    
    def process_hash(self, sha256_hash):
        """Process single hash and extract results."""
        file_data = self.query_file_hash(sha256_hash)
        
        if not file_data:
            return {
                'hash': sha256_hash,
                'found': False,
                'detections': 0,
                'engines': 0,
                'verdict': 'UNKNOWN'
            }
        
        analysis_stats = file_data.get('attributes', {}).get('last_analysis_stats', {})
        analysis_results = file_data.get('attributes', {}).get('last_analysis_results', {})
        
        malicious = analysis_stats.get('malicious', 0)
        total = analysis_stats.get('total', 0)
        
        verdict = 'CLEAN'
        if malicious >= 5:
            verdict = 'MALICIOUS'
        elif malicious >= 1:
            verdict = 'SUSPICIOUS'
        
        threat_name = ''
        for result in analysis_results.values():
            if result.get('category') == 'malicious':
                threat_name = result.get('result', 'Unknown')
                break
        
        return {
            'hash': sha256_hash,
            'found': True,
            'detections': malicious,
            'engines': total,
            'verdict': verdict,
            'threat_name': threat_name,
            'category': file_data.get('attributes', {}).get('category', 'unknown'),
            'last_analysis_date': file_data.get('attributes', {}).get('last_analysis_date')
        }
    
    def scan_hashes_from_file(self, input_file, progress_callback=None):
        """Scan multiple hashes from file with rate limiting."""
        if not Path(input_file).exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        hashes = []
        try:
            with open(input_file, 'r') as f:
                for line in f:
                    h = line.strip()
                    if h and self._validate_sha256(h):
                        hashes.append(h)
        except Exception as e:
            raise Exception(f"Failed to read input file: {e}")
        
        print(f"[*] Found {len(hashes)} valid SHA256 hashes")
        
        for idx, hash_val in enumerate(hashes, 1):
            if progress_callback:
                progress_callback(idx, len(hashes))
            else:
                print(f"[*] Scanning {idx}/{len(hashes)}: {hash_val[:16]}...")
            
            result = self.process_hash(hash_val)
            self.results.append(result)
            
            # Rate limiting
            if idx < len(hashes):
                time.sleep(self.RATE_LIMIT_DELAY)
        
        return self.results
    
    def save_results_json(self, output_file):
        """Save all results to JSON file."""
        output = {
            'timestamp': self.session_timestamp,
            'total_scanned': len(self.results),
            'malicious_found': len([r for r in self.results if r.get('verdict') == 'MALICIOUS']),
            'suspicious_found': len([r for r in self.results if r.get('verdict') == 'SUSPICIOUS']),
            'results': self.results
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(output, f, indent=2)
            print(f"[+] Results saved to: {output_file}")
        except Exception as e:
            raise Exception(f"Failed to save results: {e}")
    
    def save_alerts_file(self, output_file):
        """Save high-risk alerts (>3 engines detection) to separate file."""
        high_risk = [r for r in self.results if r.get('detections', 0) > 3]
        
        if not high_risk:
            print("[*] No high-risk alerts found")
            return
        
        alerts_output = {
            'timestamp': self.session_timestamp,
            'alert_count': len(high_risk),
            'alerts': high_risk
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(alerts_output, f, indent=2)
            print(f"[+] Alerts saved to: {output_file}")
        except Exception as e:
            raise Exception(f"Failed to save alerts: {e}")
    
    def print_summary(self):
        """Print summary of scan results."""
        if not self.results:
            print("[-] No results to summarize")
            return
        
        malicious = [r for r in self.results if r.get('verdict') == 'MALICIOUS']
        suspicious = [r for r in self.results if r.get('verdict') == 'SUSPICIOUS']
        unknown = [r for r in self.results if not r.get('found')]
        
        print("\n" + "=" * 70)
        print("VIRUSTOTAL BULK SCAN SUMMARY")
        print("=" * 70)
        print(f"Total Scanned: {len(self.results)}")
        print(f"Malicious: {len(malicious)}")
        print(f"Suspicious: {len(suspicious)}")
        print(f"Unknown: {len(unknown)}")
        print("")
        
        if malicious:
            print("HIGH-RISK DETECTIONS (MALICIOUS):")
            print("-" * 70)
            for r in malicious[:10]:
                print(f"  {r['hash'][:32]}...")
                print(f"    Detections: {r['detections']}/{r['engines']}")
                if r.get('threat_name'):
                    print(f"    Threat: {r['threat_name']}")
        
        print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description='Bulk scan multiple hashes against VirusTotal API v3',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 virustotal_bulk_scanner.py -i hashes.txt -k YOUR_API_KEY -j results.json -a alerts.json
  export VT_API_KEY='YOUR_API_KEY'
  python3 virustotal_bulk_scanner.py -i hashes.txt -j results.json
  
Input file format (one SHA256 per line):
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  da39a3ee5e6b4b0d3255bfef95601890afd80709
        """)
    
    parser.add_argument('-i', '--input', required=True, help='File with SHA256 hashes (one per line)')
    parser.add_argument('-k', '--api-key', help='VirusTotal API key (or set VT_API_KEY env var)')
    parser.add_argument('-j', '--json', help='Output JSON file for full results')
    parser.add_argument('-a', '--alerts', help='Output JSON file for high-risk alerts (>3 engines)')
    
    args = parser.parse_args()
    
    api_key = args.api_key or os.environ.get('VT_API_KEY')
    if not api_key:
        print("[-] Error: API key not provided. Set VT_API_KEY env var or use -k flag", file=sys.stderr)
        sys.exit(1)
    
    try:
        scanner = VirustotalBulkScanner(api_key)
        scanner.scan_hashes_from_file(args.input)
        scanner.print_summary()
        
        if args.json:
            scanner.save_results_json(args.json)
        
        if args.alerts:
            scanner.save_alerts_file(args.alerts)
    
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
