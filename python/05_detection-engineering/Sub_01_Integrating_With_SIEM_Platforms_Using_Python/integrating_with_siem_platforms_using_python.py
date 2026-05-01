"""
Integrating With Siem Platforms Using Python

Security operations automation tool.
"""

#
# pip install splunk-sdk
# - Service: Represents a connection to a Splunk instance (host, port, authentication).
# - Search Jobs: Submit a search string (SPL), poll until it completes, then retrieve
#   results.
import splunklib.client as client
import splunklib.results as results
# Create a Service instance to talk to Splunk
service = client.Service(
    host="splunk.example.com",
    port=8089,
    username="api_user",
    password="secret_password"
)
# Verify authentication
if not service.is_authenticated():
    raise Exception("Unable to authenticate to Splunk.")
# Create and run a search job
# This example searches for failed SSH logins in the last hour
search_query = 'search index=main sourcetype=linux_secure "Failed password" | stats count by src_ip'
job = service.jobs.create(search_query, exec_mode="blocking")
# Retrieve results
reader = results.JSONResultsReader(job.results())
for item in reader:
    if isinstance(item, dict):
        src_ip = item.get("src_ip")
        count  = item.get("count")
        print(f"Failed logins from {src_ip}: {count}")
# Commentary
# - We use `exec_mode="blocking"` for simplicity; for large searches prefer polling
#   `job.is_done` in a loop.
# - `JSONResultsReader` parses the raw JSON into Python dictionaries.
# - Always handle authentication errors and timeouts in production code.
#
# Instead of using the SDK’s port 8089, you can send raw events over HTTP to port 8088
# with a token.
# - Enable HEC in Settings → Data Inputs → HTTP Event Collector.
# - Create a new token with an index and source type.
# - Note your HEC token and endpoint URL (e.g.
#   `https://splunk.example.com:8088/services/collector`).
import requests
import json
HEC_URL = "https://splunk.example.com:8088/services/collector"
HEC_TOKEN = "YOUR_HEC_TOKEN"
def send_event(event_data, index="main", sourcetype="custom:python"):
    """
    Sends a single event to Splunk via HEC.
    event_data: dict or string
    """
    payload = {
        "index": index,
        "sourcetype": sourcetype,
        "event": event_data
    }
    headers = {
        "Authorization": f"Splunk {HEC_TOKEN}"
    }
    resp = requests.post(HEC_URL, headers=headers, json=payload, verify=True)
    if resp.status_code not in (200, 201, 202):
        raise Exception(f"HEC failed: {resp.status_code} {resp.text}")
alert = {
    "alert_name": "Malware IOC Detected",
    "ioc_type": "ip",
    "ioc_value": "198.51.100.23",
    "severity": "high",
    "source": "python-script"
}
send_event(alert)
print("Event sent to Splunk.")
# Commentary
# - You can batch multiple events in one request by sending a list of payloads.
# - Ensure your SSL certificates are valid (`verify=True`). In test environments you may
#   disable with `verify=False`.
#
#
# pip install elasticsearch
from elasticsearch import Elasticsearch
# Connect to Elasticsearch
es = Elasticsearch(
    ["https://es.example.com:9200"],
    http_auth=("elastic", "changeme"),
    scheme="https",
    port=9200
)
# Query: find alerts with severity high in the last 24h
body = {
    "query": {
        "bool": {
            "must": [
                {"match": {"severity": "high"}},
                {"range": {"@timestamp": {"gte": "now-24h"}}}
            ]
        }
    }
}
resp = es.search(index="siem-alerts", body=body)
for hit in resp["hits"]["hits"]:
    src = hit["_source"].get("source_ip")
    msg = hit["_source"].get("message")
    print(f"{src}: {msg}")
# Commentary
# - Replace index name with your SIEM’s alert index.
# - You can use aggregations to build dashboards.
#