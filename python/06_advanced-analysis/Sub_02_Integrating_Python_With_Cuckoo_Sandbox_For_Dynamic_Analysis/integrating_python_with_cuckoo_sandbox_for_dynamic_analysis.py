"""
Integrating Python With Cuckoo Sandbox For Dynamic Analysis

Security operations automation tool.
"""

#
# curl http://localhost:8090/tasks/list
import requests
CUCKOO_API = "http://localhost:8090/tasks/create/file"
# Prepare the file for submission
with open("sample.exe", "rb") as f:
    files = {"file": ("sample.exe", f)}
# Submit the file to Cuckoo
response = requests.post(CUCKOO_API, files=files)
# Parse and print the task ID
if response.ok:
    task_id = response.json()["task_id"]
    print(f"Submitted successfully. Task ID: {task_id}")
else:
    print(f"Error: {response.status_code} - {response.text}")
# - The file is submitted as multipart/form-data.
# - The API returns a JSON response containing the `task_id`, which is used to track the
#   analysis.
#
# ## 4. Checking the Status of the Analysis
import time
def check_status(task_id):
    url = f"http://localhost:8090/tasks/view/{task_id}"
    while True:
        resp = requests.get(url)
        status = resp.json()["task"]["status"]
        print(f"Current Status: {status}")
        if status == "reported":
            break
        time.sleep(5)
task_id = 1  # Replace with your actual task ID
check_status(task_id)
# - This function polls Cuckoo every 5 seconds until the analysis is complete.
# - Status options include: `pending`, `running`, `completed`, and `reported`.
#
# ## 5. Retrieving the Full Analysis Report (JSON)
def get_report(task_id):
    url = f"http://localhost:8090/tasks/report/{task_id}"
    response = requests.get(url)
    if response.ok:
        return response.json()
    else:
        raise Exception(f"Failed to get report: {response.status_code}")
report = get_report(task_id)
# - The full report includes behavioral logs, dropped files, signatures, network
#   activity, etc.
#
# ## 6. Parsing Behavioral IOCs from the Report
def extract_iocs(report):
    iocs = {
        "domains": [],
        "ips": [],
        "mutexes": [],
        "executed_commands": []
    }
    # Network section
    for domain in report.get("network", {}).get("domains", []):
        iocs["domains"].append(domain["domain"])
    for host in report.get("network", {}).get("hosts", []):
        iocs["ips"].append(host["ip"])
    # Behavioral section
    for process in report.get("behavior", {}).get("processes", []):
        for call in process.get("calls", []):
            if call["api"] == "CreateMutexW":
                arguments = call.get("arguments", [])
                for arg in arguments:
                    if arg["name"] == "MutexName":
                        iocs["mutexes"].append(arg["value"])
            elif call["api"] == "WinExec":
                for arg in call.get("arguments", []):
                    if arg["name"] == "CommandLine":
                        iocs["executed_commands"].append(arg["value"])
    return iocs
parsed_iocs = extract_iocs(report)
print("Extracted IOCs:")
for key, values in parsed_iocs.items():
    print(f"{key.upper()}: {values}")
# - Extracts indicators from both network and behavioral sections.
# - Looks for API call arguments like `CreateMutexW` and `WinExec`.
#
# ## 7. Exporting Results to JSON/CSV for External Use
import json
with open("cuckoo_iocs.json", "w") as f:
    json.dump(parsed_iocs, f, indent=2)
# Or to CSV:
import csv
with open("cuckoo_iocs.csv", "w", newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["Type", "Value"])
    for ioc_type, items in parsed_iocs.items():
        for item in items:
            writer.writerow([ioc_type, item])
# ## 8. Automating the Full Workflow
# You can wrap the entire workflow in a function:
def analyze_sample(file_path):
    with open(file_path, "rb") as f:
        response = requests.post(CUCKOO_API, files={"file": (file_path, f)})
    task_id = response.json()["task_id"]
    print(f"Submitted Task ID: {task_id}")
    check_status(task_id)
    report = get_report(task_id)
    return extract_iocs(report)
iocs = analyze_sample("sample.exe")
print(json.dumps(iocs, indent=2))