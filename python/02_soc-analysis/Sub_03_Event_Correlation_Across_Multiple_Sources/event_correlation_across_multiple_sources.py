"""
Event Correlation Across Multiple Sources

Security operations automation tool.
"""

{
    "timestamp": "2025-06-14T16:20:00Z",
    "source": "auth",
    "user": "alice",
    "event": "failed_login",
    "ip": "192.168.1.50"
}
# Let’s normalize a few sources.
import re
from datetime import datetime
def parse_auth_line(line):
    match = re.search(r"(\w+\s+\d+)\s[\d:]+\s.*Failed password.*from (\d+\.\d+\.\d+\.\d+)", line)
    if match:
        dt = datetime.strptime(f"2025 {match.group(1)}", "%Y %b %d")
        return {
            "timestamp": dt.isoformat(),
            "source": "auth",
            "event": "failed_login",
            "ip": match.group(2)
        }
    return None
#
def parse_web_line(line):
    match = re.search(r"(\d+\.\d+\.\d+\.\d+).*\[(.*?)\] \"GET (.*?)\"", line)
    if match:
        dt = datetime.strptime(match.group(2), "%d/%b/%Y:%H:%M:%S %z")
        return {
            "timestamp": dt.isoformat(),
            "source": "web",
            "event": "url_access",
            "ip": match.group(1),
            "url": match.group(3)
        }
    return None
# Save parsed logs into a common structure (e.g., list or database).
all_events = []
# Simulated reading
auth_lines = open("auth.log").readlines()
web_lines = open("access.log").readlines()
for line in auth_lines:
    event = parse_auth_line(line)
    if event: all_events.append(event)
for line in web_lines:
    event = parse_web_line(line)
    if event: all_events.append(event)
from collections import defaultdict
ip_events = defaultdict(list)
for event in all_events:
    ip_events[event["ip"]].append(event)
# Alert on IPs seen in more than one log source
for ip, events in ip_events.items():
    sources = set(event["source"] for event in events)
    if len(sources) > 1:
        print(f"[CORRELATION ALERT] IP {ip} involved in multiple sources:")
        for e in events:
            print("  ", e)
# This helps detect lateral movement or multi-vector attacks.
#
# Let’s identify sequences of events that happen close in time.
from datetime import datetime, timedelta
for ip, events in ip_events.items():
    events.sort(key=lambda x: x["timestamp"])
    for i in range(len(events) - 1):
        a, b = events[i], events[i + 1]
        if a["event"] == "failed_login" and b["event"] == "url_access" and "/admin" in b.get("url", ""):
            time_diff = datetime.fromisoformat(b["timestamp"]) - datetime.fromisoformat(a["timestamp"])
            if time_diff <= timedelta(minutes=1):
                print(f"[TIME CORRELATION] {ip} failed login then accessed admin in {time_diff}")
# Track accounts that log in from unusual IPs or use patterns seen in other accounts.
user_ips = defaultdict(set)
for event in all_events:
    if "user" in event:
        user_ips[event["user"]].add(event["ip"])
for user, ips in user_ips.items():
    if len(ips) > 2:
        print(f"[MULTIPLE IP ALERT] User {user} used multiple IPs: {ips}")
# This could indicate compromised credentials being used across locations.
#
import json
with open("correlated_events.json", "w") as f:
    json.dump(all_events, f, indent=2)
#
# Correlating events across sources is critical for:
# - Reducing alert fatigue
# - Identifying multi-stage attacks