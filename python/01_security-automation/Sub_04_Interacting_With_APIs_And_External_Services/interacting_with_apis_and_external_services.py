"""
Interacting With Apis And External Services

Security operations automation tool.
"""

import requests
ip = "8.8.8.8"
url = f"https://ipinfo.io/{ip}/json"
response = requests.get(url)
if response.status_code == 200:
    data = response.json()
    print(f"IP: {data.get('ip')}")
    print(f"City: {data.get('city')}")
    print(f"Organization: {data.get('org')}")
    print(f"Location: {data.get('loc')}")
else:
    print(f"Error {response.status_code}: {response.text}")
import requests
API_KEY = "your_api_key_here"
file_hash = "44d88612fea8a8f36de82e1278abb02f"  # EICAR test file
url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
headers = {
    "x-apikey": API_KEY
}
response = requests.get(url, headers=headers)
if response.status_code == 200:
    result = response.json()
    stats = result['data']['attributes']['last_analysis_stats']
    print("Malicious:", stats['malicious'])
    print("Suspicious:", stats['suspicious'])
else:
    print("Error:", response.status_code)
import requests
url = "https://httpbin.org/post"
payload = {
    "username": "admin",
    "action": "login"
}
response = requests.post(url, json=payload)
print("Status:", response.status_code)
print("Server Response:", response.json())
import requests
try:
    r = requests.get("https://ipinfo.io/8.8.8.8/json", timeout=5)
    r.raise_for_status()  # Raise error if response is 4xx or 5xx
    data = r.json()
    print(data)
except requests.exceptions.HTTPError as err:
    print("HTTP error:", err)
except requests.exceptions.Timeout:
    print("Request timed out")
except requests.exceptions.RequestException as e:
    print("General error:", e)
import requests
class IPInfoClient:
    def __init__(self, token=None):
        self.base_url = "https://ipinfo.io"
        self.token = token
    def lookup(self, ip):
        url = f"{self.base_url}/{ip}/json"
        params = {"token": self.token} if self.token else {}
        try:
            response = requests.get(url, params=params, timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"[!] API error: {e}")
            return None
client = IPInfoClient()
info = client.lookup("8.8.8.8")
if info:
    print(info.get("org"), info.get("city"))
engine_results = data['data']['attributes']['last_analysis_results']
for engine, result in engine_results.items():
    print(f"{engine}: {result['category']} - {result['result']}")
import logging
logging.basicConfig(filename="api.log", level=logging.INFO)
def log_ip_info(data):
    ip = data.get("ip")
    city = data.get("city")
    org = data.get("org")
    logging.info(f"{ip} - {city} - {org}")