"""
Introduction To Threat Intelligence And Python Integration

Security operations automation tool.
"""

#
# {
#   "type": "indicator",
#   "id": "indicator--1234",
#   "pattern_type": "stix",
#   "valid_from": "2025-06-14T00:00:00Z",
# }
# TAXII is a transport protocol for sharing STIX objects between servers and clients.
# Python can interface with TAXII servers using libraries like:
# - `cabby` (TAXII 1.x)
# - `taxii2-client` (TAXII 2.x)
# TAXII servers can be public (e.g., MISP) or internal.
#
# Many open threat feeds like AbuseIPDB, AlienVault OTX, or URLhaus offer raw data via:
# - JSON APIs
# - CSV dumps (updated daily)
# - Direct downloads or authenticated access
#
# dateadded,url,threat
# To work with Threat Intelligence in Python, ensure the following libraries:
#
# pip install requests pandas stix2 taxii2-client python-misp
# - `requests` – HTTP communication
# - `pandas` – CSV/JSON parsing and manipulation
# - `stix2` – STIX 2.1 object creation and parsing
# - `taxii2-client` – Access TAXII 2.x feeds
# - `python-misp` – Integration with MISP instance
#
# Here is a basic example of pulling a JSON feed:
import requests
feed_url = "https://otx.alienvault.com/api/v1/indicators/export?type=IPv4"
headers = {"X-OTX-API-KEY": "your_api_key"}
response = requests.get(feed_url, headers=headers)
if response.status_code == 200:
    with open("otx_ipv4_iocs.txt", "w") as f:
        f.write(response.text)
else:
    print("Failed to fetch feed:", response.status_code)
# Comments:
# - We request the AlienVault OTX feed of IPv4 IOCs.
# - You must authenticate with an API key.
# - Data is written to a local file for future parsing and correlation.
#
# If you receive a STIX 2.1 bundle:
from stix2 import parse
with open("example_bundle.json") as f:
    bundle = parse(f.read(), allow_custom=True)
for obj in bundle.objects:
    if obj.type == "indicator":
        print(f"[+] Indicator: {obj.pattern}")
# Commentary:
# - `parse()` auto-detects STIX object types.
# - Each object has `.type`, `.pattern`, and other attributes.
# - This allows you to filter only relevant objects (e.g., `indicator`, `malware`, etc.)
#
# Combining ingestion with simple enrichment:
import requests
import json
# Step 1: Fetch IOCs (fake example)
response = requests.get("https://example.com/iocs.json")
iocs = response.json()
# Step 2: Simple enrichment via IP geolocation
def enrich_ip(ip):
    r = requests.get(f"https://ipinfo.io/{ip}/json")
    if r.status_code == 200:
        return r.json().get("country", "Unknown")
    return "Unknown"
# Step 3: Display enriched results
for entry in iocs.get("ips", []):
    country = enrich_ip(entry)
    print(f"[{entry}] → Located in {country}")