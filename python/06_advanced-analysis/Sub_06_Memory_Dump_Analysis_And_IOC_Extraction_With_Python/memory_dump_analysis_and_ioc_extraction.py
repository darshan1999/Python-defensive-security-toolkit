"""
Memory Dump Analysis And Ioc Extraction

Security operations automation tool.
"""

#
# # winpmem -o memory.raw
# Define a basic list of regex patterns to extract IOCs commonly found in memory:
import re
# Define regex patterns for IOC types
ioc_patterns = {
    "ipv4": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,})\b", re.IGNORECASE),
    "url": re.compile(r"https?://[^\s\"']+", re.IGNORECASE),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "filepath": re.compile(rb"[A-Z]:\\[^:*?\"<>|\r\n]+")
}
# - IPs, domains, URLs, filepaths, and emails are common artifacts.
# - Regex is the fastest way to locate them in raw text buffers from memory.
#
# ## 4. Read and Scan a Memory Dump
def scan_memory_dump(file_path):
    """
    Reads a memory dump file and extracts IOCs using regex patterns.
    """
    results = {key: set() for key in ioc_patterns}
    with open(file_path, "rb") as f:
        data = f.read()
        # Convert binary to string safely for regex matching
        ascii_data = data.decode(errors="ignore")
        # Scan ASCII string content
        for key, pattern in ioc_patterns.items():
            if key != "filepath":
                matches = pattern.findall(ascii_data)
            else:
                # Filepath regex works better in raw binary mode
                matches = pattern.findall(data)
                matches = [m.decode(errors="ignore") for m in matches]
            results[key].update(matches)
    return results
# ## 5. Display the Results
def display_ioc_results(results):
    print("=== IOC Extraction Results ===")
    for ioc_type, values in results.items():
        print(f"\n{ioc_type.upper()} ({len(values)} found):")
        for val in sorted(values):
            print(" -", val)
if __name__ == "__main__":
    file_path = "memory_dump.raw"  # Replace with your actual dump file
    results = scan_memory_dump(file_path)
    display_ioc_results(results)
# You can extract additional context surrounding the IOCs:
def extract_context(data, match, window=40):
    """
    Extracts context around an IOC match (e.g., 40 bytes before and after).
    """
    index = data.find(match.encode())
    if index != -1:
        start = max(0, index - window)
        end = index + len(match) + window
        return data[start:end].decode(errors="ignore")
    return ""
# This helps analysts determine whether a URL or domain is actively used or referenced
# by malware.
#
# ## 8. Optional: Integration with Volatility Framework
# For more advanced memory parsing (processes, network sockets, DLLs), use Volatility:
#
# volatility3 -f memory.raw windows.pslist
# To automate Volatility in Python:
import subprocess
def run_volatility(plugin, dump_file):
    """
    Wrapper to execute a Volatility plugin and return its output.
    """
    cmd = ["volatility3", "-f", dump_file, plugin]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout
# ## 9. Exporting IOCs to JSON
import json
def export_to_json(results, output_file="iocs_extracted.json"):
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] IOCs exported to {output_file}")