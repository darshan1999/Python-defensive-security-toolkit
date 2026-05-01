#!/usr/bin/env python3
"""
HybridAnalysis Integration - Query Hybrid Analysis API for threat intelligence.
"""

import sys, os, argparse, json
import urllib.request, urllib.error

class HybridanalysisIntegration:
    """Query Hybrid Analysis API for file analysis results."""
    
    HA_API_URL = "https://www.hybrid-analysis.com/api/v2"
    
    def __init__(self, api_key):
        self.api_key = api_key
    
    def query_file_hash(self, sha256_hash):
        """Query Hybrid Analysis for file hash analysis."""
        url = f"{self.HA_API_URL}/search/hash?hash={sha256_hash}&type=json"
        req = urllib.request.Request(url, headers={"api-key": self.api_key, "user-agent": "Hybrid-Analysis"})
        try:
            response = urllib.request.urlopen(req)
            data = json.loads(response.read().decode())
            results = data.get("response", [])
            return results[0] if results else None
        except urllib.error.HTTPError as e:
            if e.code == 404: print(f"[-] File hash not found: {sha256_hash}")
            else: print(f"[-] API Error: {e.code}")
            return None
        except Exception as e:
            print(f"[-] Error: {e}"); return None
    
    def process(self, sha256_hash):
        """Process file hash and retrieve threat intelligence."""
        print(f"[*] Querying Hybrid Analysis for: {sha256_hash}")
        result = self.query_file_hash(sha256_hash)
        if not result: print("[-] No analysis found"); return None
        return result
    
    def _get_severity(self, threat_score):
        """Map threat score to severity."""
        if threat_score >= 80: return "CRITICAL"
        elif threat_score >= 60: return "HIGH"
        elif threat_score >= 40: return "MEDIUM"
        elif threat_score >= 20: return "LOW"
        else: return "MINIMAL"
    
    def report(self, result):
        """Display threat analysis results."""
        if not result: return
        threat_score = result.get("threat_score", 0)
        verdict = result.get("verdict", "unknown")
        print("\n" + "="*60)
        print("HYBRID ANALYSIS THREAT REPORT")
        print("="*60)
        print(f"SHA256: {result.get('sha256', 'N/A')}")
        print(f"Threat Score: {threat_score} | Severity: {self._get_severity(threat_score)}")
        print(f"Verdict: {verdict.upper()}")
        tags = result.get("tags", [])
        if tags: print(f"Tags: {', '.join(tags[:10])}")
        malware_family = result.get("vx_family", "N/A")
        if malware_family: print(f"Malware Family: {malware_family}")
        print(f"Type: {result.get('type_short', 'N/A')} | Size: {result.get('size', 'N/A')} bytes")
        print("="*60)

def main():
    if "--example" in sys.argv:
        print("Usage:\n  HA_API_KEY=key python3 hybridanalysis_integration.py <sha256_hash>"); sys.exit(0)
    parser = argparse.ArgumentParser(description="Query Hybrid Analysis API for file threat intelligence")
    parser.add_argument("sha256_hash", help="SHA256 file hash to query")
    parser.add_argument("-k", "--api-key", help="Hybrid Analysis API key (or set HA_API_KEY env var)")
    args = parser.parse_args()
    api_key = args.api_key or os.getenv("HA_API_KEY")
    if not api_key:
        print("[-] Hybrid Analysis API key not provided"); sys.exit(1)
    tool = HybridanalysisIntegration(api_key)
    result = tool.process(args.sha256_hash)
    tool.report(result)

if __name__ == "__main__":
    main()
