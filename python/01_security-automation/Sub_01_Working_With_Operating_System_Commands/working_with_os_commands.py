"""
Working With Os Commands

Security operations automation tool.
"""

import os
os.system("ping -c 4 google.com")  # On Linux/macOS
# Windows: os.system("ping -n 4 google.com")
# Pros:
# - Quick and easy for testing
# - Suitable for one-off tasks
# Cons:
# - Does not return command output
# - Security risks with unsanitized input
# - Limited error handling
# Use this method only when output isn't needed or in trusted scripts.
#
# This is the recommended modern approach.
import subprocess
result = subprocess.run(["ping", "-c", "4", "8.8.8.8"], capture_output=True, text=True)
print("Exit Code:", result.returncode)
print("Output:", result.stdout)
print("Errors:", result.stderr)
# Advantages:
# - Structured access to stdout, stderr, return code
# - Built-in support for timeouts and shell isolation
# - Enables programmatic analysis of command results
# Use `text=True` to automatically decode byte output into strings.
#
# For long-running or streaming commands, you can use `Popen`:
import subprocess
process = subprocess.Popen(["ping", "-c", "5", "google.com"], stdout=subprocess.PIPE, text=True)
for line in process.stdout:
    print(">>>", line.strip())
process.wait()
# This is particularly useful for:
# - Logging live responses from network diagnostics
# - Building TUI-based monitors or dashboards
# - Streaming logs or events to SIEM-like pipelines
#
# ## 4. Handling Interactive Tools
# Some tools expect user input (e.g., answering prompts). Use `communicate()`:
import subprocess
proc = subprocess.Popen(["some_interactive_command"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
stdout, stderr = proc.communicate("yes\n")
print(stdout)
# ## 5. Error Handling and Timeouts
# Security tools must be robust. Always implement proper error control.
import subprocess
try:
    subprocess.run(["sleep", "10"], timeout=3)
except subprocess.TimeoutExpired:
    print("Command timed out.")
result = subprocess.run(["ls", "/nonexistent"], capture_output=True, text=True)
if result.returncode != 0:
    print("Error occurred:", result.stderr)
# ## 6. Parsing Command Output
# After executing a command, parsing its output is essential for automation.
import subprocess
import re
domain = "example.com"
result = subprocess.run(["whois", domain], capture_output=True, text=True)
patterns = {
    "Registrar": r"Registrar:\s*(.+)",
    "Created": r"Creation Date:\s*(.+)",
    "Expires": r"Expiry Date:\s*(.+)"
}
for key, regex in patterns.items():
    match = re.search(regex, result.stdout)
    if match:
        print(f"{key}: {match.group(1)}")
# You can adapt this technique for any structured or semi-structured CLI output.
#
# ## 7. Cross-Platform Compatibility
# OS command syntax differs between systems. Use `platform.system()` to adapt:
import platform
import subprocess
if platform.system() == "Windows":
    cmd = ["ipconfig"]
else:
    cmd = ["ifconfig"]
subprocess.run(cmd)
# Avoid hardcoding OS-specific commands in cross-platform tools. Abstract them into
# helper functions.
#
# ## 8. Security Considerations
# Bad practice (dangerous with user input):
#
# user_input = "8.8.8.8"  # example only
# subprocess.run(f"ping {user_input}", shell=True)
# Preferred (shell=False with argv list):
#
# user_input = "8.8.8.8"  # example only
# - Always validate input (IP/domain formats)
# - Never pass unchecked user data to `shell=True`
# - Avoid using `shell=True` unless required by syntax (e.g., redirection, pipes)
#
# ## 9. Use Case: Host Availability and Domain Intel Script
import subprocess
import json
domain = "scanme.nmap.org"
# Ping check
ping = subprocess.run(["ping", "-c", "3", domain], capture_output=True, text=True)
reachable = "0% packet loss" in ping.stdout
# WHOIS data
whois = subprocess.run(["whois", domain], capture_output=True, text=True)
whois_data = {}
for line in whois.stdout.splitlines():
    for field in ["Registrar:", "Creation Date:", "Expiry Date:"]:
        if line.startswith(field):
            whois_data[field] = line.split(":", 1)[-1].strip()
report = {
    "domain": domain,
    "reachable": reachable,
    "whois": whois_data
}
print(json.dumps(report, indent=2))
# This script integrates multiple command-line tools into a structured report.
#