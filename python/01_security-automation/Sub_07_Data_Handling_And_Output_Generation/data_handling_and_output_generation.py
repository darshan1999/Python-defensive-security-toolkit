"""
Data Handling And Output Generation

Security operations automation tool.
"""

import json
with open("scan_result.json", "r") as f:
    data = json.load(f)
# Print a specific field
print("IP Address:", data["host"]["ip"])
# Use Case: Reading the results from a vulnerability scanner or threat intelligence API.
#
# CSV files are common in logs, reports, and exported data.
import csv
with open("firewall_logs.csv", newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        print(f"Source IP: {row['src_ip']}, Destination: {row['dst_ip']}")
# Use Case: Parsing firewall logs for incident correlation.
#
# Many tools output text logs that must be parsed.
with open("alerts.log") as f:
    for line in f:
        if "BLOCKED" in line:
            print("[!] Blocked traffic:", line.strip())
# Use string search, regex, or split() for structured lines:
import re
line = "2025-06-14 12:01:23 BLOCKED 192.168.1.4 -> 10.0.0.1"
match = re.search(r"BLOCKED\s+(\S+)\s+->\s+(\S+)", line)
if match:
    print("Source:", match.group(1), "Target:", match.group(2))
# You often need to transform and enrich raw data.
incident = {
    "id": "INC10293",
    "timestamp": "2025-06-14T13:45:00Z",
    "severity": "high",
    "affected_hosts": ["10.0.0.1", "10.0.0.2"],
}
incident["status"] = "open"  # Add new field
incident["affected_hosts"].append("10.0.0.3")  # Update list
print(json.dumps(incident, indent=2))  # Pretty-print
# Many security APIs return deeply nested structures. Use functions to flatten or
# simplify them.
def flatten_event(event):
    return {
        "timestamp": event["meta"]["time"],
        "ip": event["network"]["ip_src"],
        "url": event.get("network", {}).get("http_request", {}).get("url", "N/A")
    }
raw_event = {
    "meta": {"time": "2025-06-14T13:00:00Z"},
    "network": {"ip_src": "192.168.1.3", "http_request": {"url": "http://malware.com"}}
}
print(flatten_event(raw_event))
# Python can export to many formats. This is critical for:
# - Alerts
# - Dashboards
# - Compliance reports
result = {
    "host": "192.168.1.5",
    "status": "infected",
    "threat": "Ransomware",
    "timestamp": "2025-06-14T14:15:00Z"
}
with open("report.json", "w") as f:
    json.dump(result, f, indent=4)
import csv
rows = [
    {"ip": "192.168.1.1", "status": "clean"},
    {"ip": "192.168.1.2", "status": "suspicious"},
]
with open("status.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["ip", "status"])
    writer.writeheader()
    writer.writerows(rows)
with open("alerts.txt", "a") as f:
    f.write("ALERT: Malware found on host 192.168.1.5 at 14:15\n")
# Use `logging` for structured output with timestamps:
import logging
logging.basicConfig(filename="alerts.log", level=logging.INFO)
logging.info("Malware detected on 192.168.1.5")
html = """
<html>
  <head><title>Threat Report</title></head>
  <body>
    <h1>Incident Summary</h1>
    <p>Host 192.168.1.5 was infected with ransomware.</p>
  </body>
</html>
"""
with open("report.html", "w") as f:
    f.write(html)
# Use this for basic web-based alerts or management reports.
#
import json
import time
def create_report(ip, threats):
    report = {
        "generated_at": time.ctime(),
        "host": ip,
        "threats_detected": threats,
        "total_threats": len(threats)
    }
    return report
threats = [
    {"name": "CobaltStrike Beacon", "severity": "high"},
    {"name": "Suspicious Powershell", "severity": "medium"}
]
report = create_report("192.168.1.77", threats)
with open("scan_report.json", "w") as f:
    json.dump(report, f, indent=4)
# ## 5. Sanitizing and Validating Output
# Before exporting or storing data:
# - Remove sensitive fields (tokens, passwords)
# - Convert non-serializable types (e.g., datetime objects)
# - Sanitize filenames or paths
import datetime
# Convert datetime to ISO 8601 string before dumping
incident = {
    "time": datetime.datetime.now().isoformat(),
    "user": "admin",
    "event": "unauthorized_access"
}
json.dump(incident, open("incident.json", "w"))
# ## 6. Output for Integration with Other Tools
# - SIEM (Splunk, ELK) expects logs in specific format (JSON or CSV)
# - SOC Dashboards may read from a shared `status.json`
# - Email or HTTP alerts can attach/export reports
# Sending report to webhook
import requests
with open("report.json") as f:
    data = json.load(f)
requests.post("https://defense.local/api/report", json=data)