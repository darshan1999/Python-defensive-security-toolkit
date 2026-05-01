"""
Sending Events To Siem Syslog Http Json Udp

Security operations automation tool.
"""

import logging
from logging.handlers import SysLogHandler
# Configure a logger that writes to a remote syslog collector
logger = logging.getLogger("myapp")
logger.setLevel(logging.INFO)
# UDP syslog (default RFC 3164)
syslog = SysLogHandler(
    address=("siem.example.com", 514),  # SIEM syslog listener
    facility=SysLogHandler.LOG_USER      # Choose appropriate facility
)
formatter = logging.Formatter(
    fmt="%(asctime)s %(hostname)s myapp[%(process)d]: %(message)s",
    datefmt="%b %d %H:%M:%S"
)
syslog.setFormatter(formatter)
logger.addHandler(syslog)
# Send a simple event
logger.info("ALERT: Malicious IP detected: 198.51.100.23")
# Conceptual notes
# - Facility categorizes source (e.g. LOG_AUTH, LOG_LOCAL0).
# - Severity is derived from logging level (INFO→notice, WARNING→warn, ERROR→err).
# - For RFC 5424 support (structured data), use
#   `SysLogHandler(socktype=socket.SOCK_STREAM)` and custom formatting.
#
# CEF is a semi-structured format commonly used by appliances. Fields are pipe-
# delimited.
import socket
import time
def send_cef_event(host, port, cef_event):
    """
    Send a single CEF message over UDP.
    cef_event: full CEF string (including header)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(cef_event.encode(), (host, port))
    sock.close()
# Build a CEF header + extension
timestamp = time.strftime("%b %d %H:%M:%S")
cef_header = f"{timestamp} myhost CEF:0|MyCompany|MyProduct|1.0|100|Malicious IP Blocked|10|"
# Extension: key=value pairs separated by spaces
extension = "src=192.0.2.1 dst=198.51.100.23 suser=jdoe msg=\"Threat intelligence block\""
cef_message = cef_header + extension
# Send to SIEM syslog listener on UDP/514
send_cef_event("siem.example.com", 514, cef_message)
# Conceptual notes
# - CEF header fields: Vendor, Product, Version, EventID, Name, Severity.
# - Extension keys must align with your SIEM’s CEF field mapping.
#
# ## 4. Emitting LEEF-Formatted Messages
# LEEF is IBM-style event format similar to CEF.
import socket
def send_leef_event(host, port, leef_event):
    """
    Send a single LEEF message over UDP or TCP.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(leef_event.encode(), (host, port))
    sock.close()
# Build a LEEF message
leef_header = "LEEF:2.0|MyCompany|MyProduct|1.0|100|"
leef_extension = "devTime=1620000000000 src=192.0.2.1 dst=198.51.100.23 usrName=jdoe msg=BlockedByPython"
leef_message = leef_header + leef_extension
send_leef_event("siem.example.com", 514, leef_message)
# Conceptual notes
# - LEEF uses key=value pairs but differs in header and delimiter conventions.
# - Ensure your SIEM is configured to parse LEEF correctly.
#
# ## 5. Sending JSON Events over HTTP
# Modern SIEMs often provide a REST ingestion endpoint (e.g., Splunk HEC, Elastic Ingest
# API).
import requests
HEC_URL = "https://splunk.example.com:8088/services/collector/event"
HEC_TOKEN = "YOUR_TOKEN_HERE"
def send_json_event(event, index="main", sourcetype="_json"):
    """
    Send a JSON event to Splunk via HEC.
    event: Python dict or string
    """
    payload = {
        "time": time.time(),
        "host": "myhost",
        "index": index,
        "sourcetype": sourcetype,
        "event": event
    }
    headers = {"Authorization": f"Splunk {HEC_TOKEN}"}
    resp = requests.post(HEC_URL, json=payload, headers=headers, timeout=5)
    if resp.status_code not in (200, 201, 202):
        raise Exception(f"HEC error: {resp.status_code} {resp.text}")
# Send a structured JSON event
event_data = {
    "alert": "malicious_ip",
    "ip": "198.51.100.23",
    "severity": "high",
    "detected_by": "python_script"
}
send_json_event(event_data)
from elasticsearch import Elasticsearch
es = Elasticsearch(["https://es.example.com:9200"], http_auth=("elastic","changeme"))
def send_elastic_event(index, document):
    """
    Index a single document in Elasticsearch.
    """
    resp = es.index(index=index, body=document)
    if resp.get("result") not in ("created", "updated"):
        raise Exception(f"Elasticsearch ingest error: {resp}")
# Send an event to the SIEM index
doc = {
    "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "event_type": "malicious_ip",
    "ip": "198.51.100.23",
    "source": "python_script"
}
send_elastic_event("siem-alerts", doc)
# Conceptual notes
# - JSON over HTTP is firewall-friendly (port 80/443).
# - It supports rich structured data and bulk ingestion.
# - Handle retries, rate limits, and authentication securely.