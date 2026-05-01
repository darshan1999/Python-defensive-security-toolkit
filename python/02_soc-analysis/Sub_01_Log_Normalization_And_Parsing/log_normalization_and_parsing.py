"""
Log Normalization And Parsing

Security operations automation tool.
"""

#
#
# Read a log file line by line
with open("auth.log", "r") as logfile:
    for line in logfile:
        print(line.strip())
# This is the foundational step before applying any parsing or transformation logic.
#
# Python’s `re` module is powerful for parsing semi-structured and unstructured log
# formats.
import re
log_line = 'Jun 13 12:22:01 server1 sshd[12345]: Failed password for invalid user root from 192.168.1.10 port 2233 ssh2'
# Create a regex pattern with named groups
pattern = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for (invalid user )?(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)\s+ssh2'
)
match = pattern.search(log_line)
if match:
    print(match.groupdict())
# Output:
#
# {
#   "month": "Jun",
#   "day": "13",
#   "time": "12:22:01",
#   "host": "server1",
#   "user": "root",
#   "ip": "192.168.1.10",
#   "port": "2233"
# }
# Named groups help convert raw log lines into structured dictionaries easily, suitable
# for export to JSON or database.
#
# You can generalize log normalization using Python classes.
class SSHLogParser:
    def __init__(self):
        self.pattern = re.compile(
            r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for (invalid user )?(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)\s+ssh2'
        )
    def parse_line(self, line):
        match = self.pattern.search(line)
        if match:
            return match.groupdict()
        return None
parser = SSHLogParser()
with open("auth.log", "r") as f:
    for line in f:
        result = parser.parse_line(line)
        if result:
            print(result)
# Some logs are already in JSON format. In such cases, parsing is trivial.
import json
with open("cloudtrail.log", "r") as log:
    for line in log:
        event = json.loads(line)
        print(event["eventName"], event["userIdentity"]["arn"])
# For JSON logs, the challenge becomes filtering and transforming rather than parsing
# structure.
#
# Some tools export logs in CSV format:
import csv
with open("firewall.csv", newline="") as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        print(row["source_ip"], "->", row["destination_ip"], row["action"])
# Use `DictReader` to map headers to values automatically.
#
# `pandas` is efficient for tabular logs (CSV, JSON, TSV):
import pandas as pd
df = pd.read_csv("ids_logs.csv")
suspicious = df[df["signature"].str.contains("SQL Injection")]
print(suspicious[["timestamp", "src_ip", "signature"]])
# This enables filtering, aggregation, and export in one unified pipeline.
#
# It’s best practice to convert logs to a normalized structure like:
#
# {
#   "timestamp": "2025-06-13T12:22:01Z",
#   "source": "sshd",
#   "host": "server1",
#   "user": "root",
#   "ip": "192.168.1.10",
#   "port": 2233,
#   "event": "failed_login"
# }
# You can convert parsed fields to this format programmatically.
#
import json
with open("parsed_logs.json", "w") as f:
    json.dump(parsed_data_list, f, indent=2)
import csv
with open("parsed_logs.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["timestamp", "user", "ip", "port", "event"])
    writer.writeheader()
    writer.writerows(parsed_data_list)
# Always wrap your parsers with exception handling:
def safe_parse(line, parser):
    try:
        return parser(line)
    except Exception as e:
        print("Parsing error:", e)
        return None
# Let’s combine parsing + aggregation:
from collections import Counter
ips = []
with open("auth.log") as f:
    for line in f:
        match = parser.parse_line(line)
        if match:
            ips.append(match["ip"])
top_ips = Counter(ips).most_common(5)
for ip, count in top_ips:
    print(f"{ip}: {count} failed attempts")
# Create a Python script that:
# - Reads a syslog file.
# - Parses failed SSH login attempts.
# - Normalizes to a dictionary format.