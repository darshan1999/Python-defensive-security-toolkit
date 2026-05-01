#!/usr/bin/env python3
"""
CSV IP Enricher - Enrich IP addresses in CSV with geolocation data.
"""

import sys, argparse, csv, json
import urllib.request, urllib.error

class CsvIpEnricher:
    """Enrich CSV data with IP geolocation information."""
    
    IP_API_URL = "http://ip-api.com/batch"
    BATCH_SIZE = 100
    
    def __init__(self):
        self.enriched_rows = []
    
    def enrich_ips_batch(self, ip_list):
        """Query ip-api.com for multiple IPs in batch."""
        results_map = {}
        for i in range(0, len(ip_list), self.BATCH_SIZE):
            batch = ip_list[i:i+self.BATCH_SIZE]
            payload = json.dumps([{"query": ip} for ip in batch]).encode()
            req = urllib.request.Request(self.IP_API_URL, data=payload, headers={"Content-Type": "application/json"})
            try:
                data = json.loads(urllib.request.urlopen(req).read().decode())
                for result in data:
                    qip = result.get("query")
                    if result.get("status") == "success":
                        results_map[qip] = {k: result.get(k.lower(), "N/A") for k in ["country", "city", "isp"]}
                        results_map[qip]["asn"] = result.get("as", "N/A")
                    else:
                        results_map[qip] = {"country": "Unknown", "city": "Unknown", "isp": "Unknown", "asn": "Unknown"}
            except Exception as e:
                print(f"[-] Error: {e}")
                for ip in batch: results_map[ip] = {"country": "Error", "city": "Error", "isp": "Error", "asn": "Error"}
        return results_map
    
    def process(self, input_file, ip_column, output_file):
        """Read CSV, enrich IPs, write output CSV."""
        try:
            with open(input_file, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                if ip_column not in reader.fieldnames:
                    print(f"[-] Column '{ip_column}' not found"); sys.exit(1)
                rows = list(reader)
            
            ips = list(set(row.get(ip_column, "").strip() for row in rows if row.get(ip_column, "").strip()))
            print(f"[*] Found {len(rows)} rows with {len(ips)} unique IPs")
            enrichment_data = self.enrich_ips_batch(ips)
            
            for row in rows:
                ip = row.get(ip_column, "").strip()
                enrichment = enrichment_data.get(ip, {"country": "N/A", "city": "N/A", "isp": "N/A", "asn": "N/A"})
                row.update({"country": enrichment["country"], "city": enrichment["city"], "ISP": enrichment["isp"], "ASN": enrichment["asn"]})
                self.enriched_rows.append(row)
            
            with open(output_file, "w", encoding="utf-8", newline="") as f:
                fieldnames = reader.fieldnames + ["country", "city", "ISP", "ASN"]
                csv.DictWriter(f, fieldnames=fieldnames).writeheader()
                csv.DictWriter(f, fieldnames=fieldnames).writerows(self.enriched_rows)
            print(f"[+] Output written to: {output_file}")
        except FileNotFoundError:
            print(f"[-] File not found: {input_file}"); sys.exit(1)
        except Exception as e:
            print(f"[-] Error: {e}"); sys.exit(1)
    
    def report(self):
        """Display enrichment summary."""
        if not self.enriched_rows: return
        countries = set(row.get("country", "N/A") for row in self.enriched_rows)
        print("\n" + "="*60)
        print(f"CSV IP ENRICHMENT | Rows: {len(self.enriched_rows)} | Countries: {len(countries)}")
        print("="*60)

def main():
    if "--example" in sys.argv:
        print("Usage:\n  python3 csv_ip_enricher.py input.csv src_ip -o output.csv"); sys.exit(0)
    parser = argparse.ArgumentParser(description="Enrich CSV with IP geolocation data")
    parser.add_argument("input_csv", help="Input CSV file path")
    parser.add_argument("ip_column", help="Column name with IPs")
    parser.add_argument("-o", "--output", help="Output CSV file path", required=True)
    args = parser.parse_args()
    tool = CsvIpEnricher()
    tool.process(args.input_csv, args.ip_column, args.output)
    tool.report()

if __name__ == "__main__":
    main()
