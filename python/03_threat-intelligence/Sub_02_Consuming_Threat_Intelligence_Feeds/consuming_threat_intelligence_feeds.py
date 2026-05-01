"""
Consuming Threat Intelligence Feeds

Security operations automation tool.
"""

#
# pip install requests pandas stix2 taxii2-client python-misp
# - `requests`: HTTP clients for pulling REST feeds
# - `pandas`: CSV parsing and analysis
# - `stix2`: Create/parse STIX indicators
# - `taxii2-client`: Interact with TAXII servers
# - `python-misp`: Query and parse data from MISP
#
# Most commercial and open-source STIX feeds are served over TAXII.
from taxii2client.v21 import Server
# Connect to a public TAXII server
server = Server("https://cti.taxii.org/taxii/")
# List API roots
api_root = server.api_roots[0]  # Usually default API root
# Discover collections
collections = api_root.collections
print("[+] Available Collections:")
for coll in collections:
    print(f"  - {coll.title}")
# Pull a bundle of objects from a collection
collection = collections[0]
objects = collection.get_objects()
for obj in objects['objects']:
    if obj['type'] == 'indicator':
        print(f"[!] Indicator: {obj['pattern']} (Labels: {obj['labels']})")
# Explanation:
# - Establishes a connection to a TAXII 2.0 server.
# - Queries collections and retrieves STIX bundles.
# - Filters objects of type `"indicator"` for printing.
#
# CSV feeds are often updated hourly or daily.
import pandas as pd
url = "https://urlhaus.abuse.ch/downloads/csv/"
df = pd.read_csv(url, comment="#", encoding="utf-8")
# Filter recent malware URLs
malicious = df[df['threat'].notnull()][['dateadded', 'url', 'threat']]
print(malicious.head())
# 💡 Notes:
# - `comment="#"` skips metadata headers.
# - Easy filtering for specific `threat` types (e.g., ransomware, trojans).
#
# AlienVault OTX provides API access with token authentication.
import requests
API_KEY = "your_otx_api_key"
headers = {"X-OTX-API-KEY": API_KEY}
r = requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed", headers=headers)
if r.status_code == 200:
    data = r.json()
    for pulse in data["results"]:
        print(f"[+] Pulse: {pulse['name']}")
        for indicator in pulse['indicators']:
            print(f"    → {indicator['type']}: {indicator['indicator']}")
else:
    print("Failed to fetch OTX pulses.")
# This script:
# - Authenticates using your API key.
# - Retrieves all subscribed threat “pulses.”
# - Prints indicator type and values (IP, domain, hash, etc.).
#
# MISP (Malware Information Sharing Platform) is a widely used open-source threat
# sharing platform.
from pymisp import ExpandedPyMISP
misp_url = "https://misp.example.com/"
misp_key = "your_api_key"
misp = ExpandedPyMISP(misp_url, misp_key, ssl=False)
# Search for events containing a specific IP
events = misp.search('attributes', value="8.8.8.8")
for event in events:
    print(f"[+] Event ID: {event['Event']['id']} - Info: {event['Event']['info']}")
# 📌 Important:
# - Ensure `ssl=False` only in trusted lab/dev environments.
# - You can also search by tag, attribute type (e.g., `md5`, `hostname`).
#
normalized = {
    "indicator": "1.1.1.1",
    "type": "ipv4-addr",
    "source": "AlienVault",
    "confidence": "high",
    "tags": ["botnet", "command-and-control"]
}
# Use tools like `cron`, `schedule`, or `Celery` to automate periodic ingestion.
#
# ## 8. Outputting Ingested IOCs
# Export parsed feeds to formats useful for SIEMs, SOARs, or dashboards.
import json
with open("output_iocs.json", "w") as f:
    json.dump(ioc_list, f, indent=2)
# Or write to CSV:
import csv
with open("output.csv", "w", newline='') as f:
    writer = csv.DictWriter(f, fieldnames=["indicator", "type", "source"])
    writer.writeheader()
    for item in ioc_list:
        writer.writerow(item)