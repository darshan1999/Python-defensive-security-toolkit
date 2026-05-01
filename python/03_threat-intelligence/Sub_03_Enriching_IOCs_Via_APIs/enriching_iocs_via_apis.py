"""
Enriching Iocs Via Apis

Security operations automation tool.
"""

import requests
API_KEY = "your_abuseipdb_key"
ip = "45.33.32.156"
url = "https://api.abuseipdb.com/api/v2/check"
params = {
    "ipAddress": ip,
    "maxAgeInDays": 90
}
headers = {
    "Accept": "application/json",
    "Key": API_KEY
}
response = requests.get(url, headers=headers, params=params)
data = response.json()["data"]
# Print useful fields
print("IP:", data["ipAddress"])
print("Abuse Confidence Score:", data["abuseConfidenceScore"])
print("Country:", data["countryCode"])
print("Usage Type:", data["usageType"])
print("Domain:", data["domain"])
# This provides insight into the IP’s risk level and its hosting behavior.
#
# VirusTotal is a well-known platform that aggregates AV scan results, sandbox data, and
# file metadata.
import requests
API_KEY = "your_virustotal_key"
hash_value = "44d88612fea8a8f36de82e1278abb02f"  # EICAR test file hash
headers = {
    "x-apikey": API_KEY
}
url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
response = requests.get(url, headers=headers)
if response.status_code == 200:
    data = response.json()
    print("Malicious Detections:", data['data']['attributes']['last_analysis_stats']['malicious'])
    print("File Type:", data['data']['attributes']['type_description'])
    print("Meaningful Name:", data['data']['attributes'].get("meaningful_name"))
else:
    print("Not found or quota exceeded.")
# Always obey rate limits and privacy guidelines with VirusTotal.
#
# ## 4. Enriching Domains: Passive DNS using SecurityTrails
import requests
API_KEY = "your_securitytrails_key"
domain = "example.com"
url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
headers = {
    "APIKEY": API_KEY
}
r = requests.get(url, headers=headers)
data = r.json()
print("Subdomains discovered:")
for subdomain in data["subdomains"]:
    print(f" - {subdomain}.{domain}")
# This API gives visibility into infrastructure potentially related to the target
# domain.
#
# ## 5. Greynoise IP Context API
# Greynoise reveals if an IP has been observed scanning or engaging in malicious
# behavior.
import requests
API_KEY = "your_greynoise_key"
ip = "45.33.32.156"
headers = {
    "key": API_KEY,
    "accept": "application/json"
}
url = f"https://api.greynoise.io/v3/community/{ip}"
r = requests.get(url, headers=headers)
data = r.json()
print("Classification:", data["classification"])
print("Name:", data["name"])
print("Link:", data["link"])
# This is helpful for rapid triage of scanning IPs.
#
# ## 6. ASN and Geolocation Enrichment: IPinfo
import requests
ip = "8.8.8.8"
response = requests.get(f"https://ipinfo.io/{ip}/json")
data = response.json()
print("IP:", data["ip"])
print("City:", data.get("city"))
print("Region:", data.get("region"))
print("Country:", data.get("country"))
print("ASN:", data.get("org"))
# Provides ownership, location, and usage data which can indicate infrastructure
# patterns.
#
# ## 7. Normalization of Enrichment Output
# Because each API returns different structures, standardize them:
enriched = {
    "ioc": "8.8.8.8",
    "type": "ip",
    "abuse_score": 0,
    "greynoise_classification": "benign",
    "country": "US",
    "asn": "Google LLC",
    "virustotal_malicious": 0,
    "sources": ["abuseipdb", "greynoise", "ipinfo"]
}
# You can wrap this into a function to handle multiple IOCs and outputs.
#
# ## 8. Combining Multiple Enrichments for a Single IOC
def enrich_ip(ip):
    results = {"ioc": ip, "type": "ip"}
    # AbuseIPDB
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip, "maxAgeInDays": 90},
                         headers={"Accept": "application/json", "Key": API_KEY})
        results["abuse_score"] = r.json()["data"]["abuseConfidenceScore"]
    except:
        results["abuse_score"] = None
    # IPinfo
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json")
        j = r.json()
        results["country"] = j.get("country")
        results["asn"] = j.get("org")
    except:
        results["country"] = results["asn"] = None
    return results
# This approach abstracts the complexity behind reusable logic for enrichment.
#
# ## 9. Exporting Enriched Data
# Export the enriched indicators to CSV or JSON for SIEM ingestion or dashboarding.
import json
with open("enriched_iocs.json", "w") as f:
    json.dump([enriched], f, indent=2)
# Or to CSV:
import csv
with open("enriched_iocs.csv", "w", newline='') as f:
    writer = csv.DictWriter(f, fieldnames=enriched.keys())
    writer.writeheader()
    writer.writerow(enriched)