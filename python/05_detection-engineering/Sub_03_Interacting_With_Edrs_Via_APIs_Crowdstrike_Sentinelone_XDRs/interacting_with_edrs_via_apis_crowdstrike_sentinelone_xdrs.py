"""
Interacting With Edrs Via Apis Crowdstrike Sentinelone Xdrs

Security operations automation tool.
"""

import requests
# Replace these with your CrowdStrike API credentials
CLIENT_ID     = "your_client_id"
CLIENT_SECRET = "your_client_secret"
OAUTH_URL     = "https://api.crowdstrike.com/oauth2/token"
def get_falcon_token(client_id, client_secret):
    """
    Obtain an OAuth2 token from CrowdStrike Falcon.
    """
    data = {
        'client_id': client_id,
        'client_secret': client_secret
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(OAUTH_URL, data=data, headers=headers)
    response.raise_for_status()  # Raise on HTTP error
    token = response.json().get('access_token')
    return token
token = get_falcon_token(CLIENT_ID, CLIENT_SECRET)
print("Access token acquired.")
# Base URL for Falcon API endpoints
BASE_URL = "https://api.crowdstrike.com"
def list_detections(token, limit=10):
    """
    Query the Falcon detection summary endpoint.
    """
    url = f"{BASE_URL}/detects/queries/detects/v1"
    headers = {'Authorization': f"Bearer {token}"}
    params = {'limit': limit}
    # First, obtain list of detection IDs
    resp = requests.get(url, headers=headers, params=params)
    resp.raise_for_status()
    detect_ids = resp.json().get('resources', [])
    # Fetch details for those detection IDs
    details_url = f"{BASE_URL}/detects/entities/detects/v1"
    params = {'ids': detect_ids}
    resp = requests.get(details_url, headers=headers, params=params)
    resp.raise_for_status()
    return resp.json().get('resources', [])
detections = list_detections(token, limit=5)
for d in detections:
    print(f"Detection ID: {d['detect_id']}, Status: {d['status']}")
def isolate_host(token, device_id):
    """
    Instruct Falcon to isolate a host by its device ID.
    """
    url = f"{BASE_URL}/devices/entities/devices-actions/v2"
    headers = {'Authorization': f"Bearer {token}", 'Content-Type': 'application/json'}
    body = {
        "device_ids": [device_id],
        "action_name": "isolate"
    }
    resp = requests.post(url, headers=headers, json=body)
    resp.raise_for_status()
    print(f"Isolation requested for device {device_id}")
if detections:
    example_device = detections[0].get('device_id')
    isolate_host(token, example_device)
import requests
# Your SentinelOne API token and site URL
API_TOKEN = "your_sentinelone_token"
SITE_URL  = "https://usea1-partners.sentinelone.net/web/api/v2.1"
def sentinel_request(endpoint, params=None, method='GET', body=None):
    """
    Helper function to call SentinelOne API endpoints.
    """
    url = f"{SITE_URL}/{endpoint}"
    headers = {
        'Authorization': f"APIToken {API_TOKEN}",
        'Content-Type': 'application/json'
    }
    if method == 'GET':
        resp = requests.get(url, headers=headers, params=params)
    elif method == 'POST':
        resp = requests.post(url, headers=headers, json=body)
    else:
        raise ValueError("Unsupported HTTP method")
    resp.raise_for_status()
    return resp.json()
# Test connectivity
resp = sentinel_request("agents")
print(f"Total agents: {resp.get('data', {}).get('totalCount')}")
def list_threats():
    """
    Retrieve recent threat records from SentinelOne.
    """
    resp = sentinel_request("threats", params={'limit': 10})
    return resp.get('data', [])
threats = list_threats()
for t in threats:
    print(f"Threat ID: {t['id']}, Status: {t['status']}, Type: {t['threatType']}")
def quarantine_agent(agent_id):
    """
    Quarantine (isolate) a SentinelOne agent by its ID.
    """
    endpoint = f"agents/{agent_id}/quarantine"
    resp = sentinel_request(endpoint, method='POST')
    print(f"Quarantine action: {resp.get('data')}")
if threats:
    example_agent = threats[0]['agentId']
    quarantine_agent(example_agent)
# - Token Security: Store API keys in environment variables or secure vaults, never in
#   code.
# - Error Handling: Wrap API calls in try/except, handle 4xx/5xx HTTP status codes,
#   implement retries with exponential back-off.