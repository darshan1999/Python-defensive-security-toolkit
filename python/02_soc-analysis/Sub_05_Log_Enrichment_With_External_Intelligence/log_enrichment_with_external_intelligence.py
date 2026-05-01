"""
Log Enrichment With External Intelligence

Security operations automation tool.
"""

#
# 192.168.1.10 -> 104.244.42.1:443 (allowed)
# We want to enrich the IP `104.244.42.1` with ASN info, geolocation, and threat score.
#
import requests
def enrich_with_ip_api(ip):
    url = f"http://ip-api.com/json/{ip}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return {
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "org": data.get("org"),
            "asn": data.get("as")
        }
    else:
        return {"error": "Lookup failed"}
ip_data = enrich_with_ip_api("104.244.42.1")
print(ip_data)
# 🛈 Commentary: This simple function queries `ip-api.com`, which does not require an API
# key. It retrieves key enrichment data like country, city, and ASN.
#
import requests
API_KEY = "your_abuseipdb_api_key"
def lookup_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    response = requests.get(url, headers=headers, params=params)
    return response.json()
abuse_data = lookup_abuseipdb("104.244.42.1")
print(abuse_data['data']['abuseConfidenceScore'])
# 🛈 Commentary: This score helps prioritize alerts. A score above 70 usually indicates
# confirmed abuse.
#
import shodan
API_KEY = "your_shodan_key"
api = shodan.Shodan(API_KEY)
try:
    result = api.host("104.244.42.1")
    print("Open Ports:", result["ports"])
    print("OS Detected:", result.get("os"))
except shodan.APIError as e:
    print("Error:", e)
# 🛈 Commentary: Shodan helps you understand the exposed services and fingerprinting of
# an IP, which can be essential during incident validation.
#
import json
def enrich_log_entry(entry):
    ip = entry.get("dst_ip")
    geo = enrich_with_ip_api(ip)
    abuse = lookup_abuseipdb(ip)
    score = abuse['data']['abuseConfidenceScore']
    entry.update({
        "geo_country": geo.get("country"),
        "asn": geo.get("asn"),
        "abuse_score": score
    })
    return entry
log = {"src_ip": "192.168.1.10", "dst_ip": "104.244.42.1", "action": "allowed"}
result = enrich_log_entry(log)
print(json.dumps(result, indent=2))
# - Rate Limits: Respect API rate limits to avoid bans
# - Caching: Cache IP lookups locally to reduce API calls
# - Privacy: Ensure sensitive data is handled per policy (GDPR, LGPD)
# - Error Handling: Always add fallback if external services fail