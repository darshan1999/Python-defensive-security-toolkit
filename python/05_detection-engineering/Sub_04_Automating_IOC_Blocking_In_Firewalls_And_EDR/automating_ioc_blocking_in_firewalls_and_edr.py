"""
Automating Ioc Blocking In Firewalls And Edr

Security operations automation tool.
"""

#
# pip install fortiosapi
from fortiosapi import FortiOSAPI
# Firewall connection details
FGT_HOST     = "https://firewall.example.com"
FGT_USERNAME = "api_user"
FGT_PASSWORD = "secure_password"
# The IOC to block
malicious_ip = "203.0.113.45"
# Name for the address object
object_name = f"IOC_{malicious_ip}"
# Name of the address-group used by your block policy
group_name = "IOC-Blacklist"
# 1. Authenticate
fos = FortiOSAPI()
fos.debug('off')  # turn on for troubleshooting
fos.login(FGT_HOST, FGT_USERNAME, FGT_PASSWORD)
# 2. Create or update a firewall address object for the IOC
fos.set(
    'firewall', 'address',
    mkey=object_name,
    data={
        'name': object_name,
        'subnet': f"{malicious_ip}/32",
        'type': 'ipmask',
        'visibility': 'enable'
    }
)
# 3. Ensure that address-object is a member of the block group
fos.set(
    'firewall', 'addrgrp',
    mkey=group_name,
    data={
        'name': group_name,
        'member': [{'name': object_name}]
    }
)
# 4. (Optional) Commit a policy change or trigger a reload if needed
#    Many FortiGate setups apply changes immediately.
# 5. Logout
fos.logout()
print(f"Blocked {malicious_ip} on FortiGate in group {group_name}")
# Commentary
# - `mkey` is the “managed key” (unique ID) for the object.
# - We use `/32` subnet for a single IP.
# - The `addrgrp` call appends or updates the address‐group.
# - Ensure a security policy references `IOC-Blacklist` in its destination address.
#
# CrowdStrike Falcon supports network containment, isolating the endpoint’s network
# traffic (except to the Falcon cloud). While not blocking individual IPs, it
# effectively prevents any further external communication.
import requests
CLIENT_ID     = "your_client_id"
CLIENT_SECRET = "your_client_secret"
OAUTH_URL     = "https://api.crowdstrike.com/oauth2/token"
def get_falcon_token():
    data = {'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET}
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    resp = requests.post(OAUTH_URL, data=data, headers=headers)
    resp.raise_for_status()
    return resp.json()['access_token']
token = get_falcon_token()
def contain_host(device_id, expire_seconds=3600):
    """
    Place an endpoint into network containment for a duration.
    """
    url = "https://api.crowdstrike.com/devices/entities/containment/v1"
    headers = {
        'Authorization': f"Bearer {token}",
        'Content-Type': 'application/json'
    }
    body = {
        "device_ids": [device_id],
        "parameters": {"expire_in": expire_seconds}
    }
    resp = requests.post(url, headers=headers, json=body)
    resp.raise_for_status()
    print(f"Host {device_id} contained for {expire_seconds} seconds")
example_device_id = "abcdef12-3456-7890-abcd-ef1234567890"
contain_host(example_device_id)
# Commentary
# - CrowdStrike’s “containment” equals isolation at the network level.
# - The `expire_in` parameter defines how long the isolation lasts.
# - For true IOC blocking (specific IP/domain), you’d combine containment with firewall
#   updates or EDR policy pushes.
#
# ## 4. Putting It Together: Automated IOC Pipeline
# Below is a simplified pipeline that:
# - Fetches new malicious IPs from a threat feed (pseudo-code)
# - Blocks them on the firewall
# - Isolates hosts that communicated with them
import requests
THREAT_FEED_URL = "https://threat-feed.example.com/iocs.csv"
def fetch_iocs():
    resp = requests.get(THREAT_FEED_URL)
    resp.raise_for_status()
    # Parse CSV of IPs
    return [line.strip() for line in resp.text.splitlines() if line]
def main():
    iocs = fetch_iocs()
    firewall = FortiOSAPI(); firewall.login(FGT_HOST, FGT_USERNAME, FGT_PASSWORD)
    cs_token = get_falcon_token()
    for ip in iocs:
        # 1. Block on Firewall
        addr_name = f"IOC_{ip}"
        firewall.set('firewall','address', mkey=addr_name, data={'name':addr_name,'subnet':f"{ip}/32","type":"ipmask"})
        firewall.set('firewall','addrgrp', mkey=group_name, data={'name':group_name,'member':[{'name':addr_name}]})
        print(f"Blocked {ip} at perimeter")
        # 2. Identify endpoints that have communicated with this IP
        #    (In practice query EDR telemetry; here we use a stub)
        affected_devices = lookup_devices_communicated_with(ip)
        # 3. Isolate those endpoints
        for dev in affected_devices:
            contain_host(dev, expire_seconds=7200)
    firewall.logout()
if __name__ == "__main__":
    main()
# `lookup_devices_communicated_with` would be implemented by querying EDR telemetry or
# SIEM logs for endpoints having outbound sessions to the IOC.
#