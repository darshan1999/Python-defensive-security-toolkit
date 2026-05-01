"""
Detection Of Suspicious Behavior

Security operations automation tool.
"""

#
import re
from collections import defaultdict
logfile = "auth.log"
failed_attempts = defaultdict(int)
pattern = re.compile(r"Failed password.*from (?P<ip>\d+\.\d+\.\d+\.\d+)")
with open(logfile, "r") as f:
    for line in f:
        match = pattern.search(line)
        if match:
            ip = match.group("ip")
            failed_attempts[ip] += 1
# Show IPs with 5 or more failures
for ip, count in failed_attempts.items():
    if count >= 5:
        print(f"[ALERT] Suspicious IP: {ip} with {count} failed logins")
# This mimics a basic brute-force detection logic found in many intrusion detection
# systems (IDS).
#
# Some attacks happen at odd hours (e.g., 2 AM). Let's flag logins outside business
# hours (8 AM - 6 PM).
import datetime
import re
time_pattern = re.compile(r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*Accepted password for (?P<user>\w+)")
month_to_num = {"Jun": 6}  # Expand as needed
with open("auth.log") as f:
    for line in f:
        match = time_pattern.search(line)
        if match:
            time_str = match.group("time")
            hour = int(time_str.split(":")[0])
            if hour < 8 or hour > 18:
                print(f"[SUSPICIOUS LOGIN] At {time_str} by {match.group('user')}")
# Let’s assume we’re watching a file audit log:
#
# accessed /etc/shadow by root
# accessed /etc/passwd by user1
# accessed /var/www/html/index.php by www-data
sensitive = ["/etc/shadow", "/etc/passwd"]
with open("file_audit.log") as f:
    for line in f:
        for path in sensitive:
            if path in line:
                print("[ALERT] Sensitive file accessed:", line.strip())
# Identify attacker tools or suspicious binaries in logs (e.g., `wget`, `curl`,
# `netcat`).
indicators = ["wget", "curl", "nc", "nmap", "python -m http.server", "scp", "sshpass"]
with open("bash_history.log") as f:
    for line in f:
        if any(cmd in line for cmd in indicators):
            print("[SUSPICIOUS CMD]", line.strip())
# Sometimes the sequence of events matters more than single lines.
# - There are failed login attempts from an IP, and then
# - A successful login from the same IP
# ...it may indicate a successful brute-force.
import re
from collections import defaultdict
failures = defaultdict(int)
successes = {}
with open("auth.log") as f:
    for line in f:
        if "Failed password" in line:
            match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                ip = match.group(1)
                failures[ip] += 1
        elif "Accepted password" in line:
            match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                ip = match.group(1)
                successes[ip] = True
for ip in successes:
    if failures[ip] >= 5:
        print(f"[CORRELATED ALERT] Brute-force followed by success from {ip}")
# Monitor unusually large downloads or transfers.
# Assuming this CSV structure:
#
# timestamp,user,file,bytes_transferred
# 2025-06-14T10:11:00Z,alice,secrets.zip,10500000
import csv
threshold = 10 * 1024 * 1024  # 10 MB
with open("downloads.csv") as f:
    reader = csv.DictReader(f)
    for row in reader:
        if int(row["bytes_transferred"]) > threshold:
            print(f"[EXFIL ALERT] {row['user']} downloaded {row['file']} of size {row['bytes_transferred']} bytes")
from collections import defaultdict
user_actions = defaultdict(list)
with open("activity.log") as f:
    for line in f:
        if "accessed" in line:
            user = line.split("by")[-1].strip()
            user_actions[user].append(line.strip())
for user, actions in user_actions.items():
    if len(actions) > 10:
        print(f"[ALERT] Unusual activity by {user}: {len(actions)} actions")
# Export alerts to JSON for SIEM ingestion.
import json
alerts = [
    {"type": "brute_force", "ip": "192.168.1.10", "attempts": 8},
    {"type": "sensitive_file", "user": "root", "file": "/etc/shadow"}
]
with open("alerts.json", "w") as f:
    json.dump(alerts, f, indent=2)
# Suspicious behavior detection is essential to modern defensive security. It enables:
# - Faster incident triage
# - Proactive threat hunting
# - Automated alerts in SIEMs and SOAR platforms