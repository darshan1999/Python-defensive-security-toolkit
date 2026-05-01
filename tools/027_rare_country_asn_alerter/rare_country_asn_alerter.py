#!/usr/bin/env python3
"""
Rare Country/ASN Alerter - Alert on connections from unexpected geographies.
"""

import sys, argparse, json
import urllib.request, urllib.error

class RareCountryAsnAlerter:
    """Alert on connections from rare/unexpected countries and ASNs."""
    
    IP_API_URL = "http://ip-api.com/batch"
    DEFAULT_ALLOWLIST = ["CA", "US", "GB"]
    
    def __init__(self, allowlist=None):
        self.allowlist = allowlist or self.DEFAULT_ALLOWLIST
        self.alerts = []
    
    def query_ip_geolocation(self, ip_list):
        """Query geolocation for IPs."""
        results_map = {}
        payload = json.dumps([{"query": ip} for ip in ip_list]).encode()
        req = urllib.request.Request(self.IP_API_URL, data=payload, headers={"Content-Type": "application/json"})
        try:
            data = json.loads(urllib.request.urlopen(req).read().decode())
            for result in data:
                if result.get("status") == "success":
                    qip = result.get("query")
                    results_map[qip] = {
                        "country": result.get("country", "Unknown"),
                        "country_code": result.get("countryCode", "XX"),
                        "city": result.get("city", "Unknown"),
                        "asn": result.get("as", "Unknown"),
                        "isp": result.get("isp", "Unknown")
                    }
        except Exception as e:
            print(f"[-] Error: {e}")
        return results_map
    
    def parse_log_file(self, log_file, ip_column=None):
        """Parse log file and extract IPs."""
        ips = []
        try:
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    ip = (line.split(",")[ip_column] if ip_column else line.split()[0]) if (ip_column or line.split()) else None
                    if ip and self._is_valid_ip(ip): ips.append(ip.strip())
            return list(set(ips))
        except FileNotFoundError:
            print(f"[-] File not found: {log_file}"); sys.exit(1)
    
    def _is_valid_ip(self, ip):
        """Basic IP validation."""
        try: return all(0 <= int(p) <= 255 for p in ip.split(".")) and len(ip.split(".")) == 4
        except: return False
    
    def process(self, log_file, ip_column=None):
        """Process log file and identify rare country/ASN connections."""
        print(f"[*] Reading log file: {log_file}")
        ips = self.parse_log_file(log_file, ip_column)
        print(f"[*] Found {len(ips)} unique IPs")
        geo_data = self.query_ip_geolocation(ips)
        
        for ip, geo in geo_data.items():
            cc = geo.get("country_code", "XX")
            if cc not in self.allowlist:
                self.alerts.append({
                    "ip": ip,
                    "country": geo.get("country"),
                    "country_code": cc,
                    "city": geo.get("city"),
                    "asn": geo.get("asn"),
                    "isp": geo.get("isp"),
                    "severity": "HIGH" if cc in ["KP", "IR", "SY"] else "MEDIUM"
                })
        return self.alerts
    
    def report(self):
        """Display alert report."""
        if not self.alerts:
            print("[+] No rare country/ASN connections detected"); return
        print("\n" + "="*80)
        print(f"RARE COUNTRY/ASN ALERT | Total: {len(self.alerts)} | Allowlist: {', '.join(self.allowlist)}")
        print("="*80)
        for alert in sorted(self.alerts, key=lambda x: x["severity"], reverse=True):
            print(f"[{alert['severity']}] {alert['ip']} - {alert['country']} ({alert['country_code']}) | City: {alert['city']} | ASN: {alert['asn']}")
        print("="*80)

def main():
    if "--example" in sys.argv:
        print("Usage:\n  python3 rare_country_asn_alerter.py access.log\n  python3 rare_country_asn_alerter.py events.log -a US CA GB"); sys.exit(0)
    parser = argparse.ArgumentParser(description="Alert on IP connections from unexpected geographies")
    parser.add_argument("log_file", help="Log file with IPs")
    parser.add_argument("-a", "--allowlist", nargs="+", help="Allowed country codes")
    parser.add_argument("-c", "--ip-column", type=int, help="CSV column index")
    args = parser.parse_args()
    allowlist = args.allowlist or RareCountryAsnAlerter.DEFAULT_ALLOWLIST
    tool = RareCountryAsnAlerter(allowlist)
    tool.process(args.log_file, args.ip_column)
    tool.report()

if __name__ == "__main__":
    main()
