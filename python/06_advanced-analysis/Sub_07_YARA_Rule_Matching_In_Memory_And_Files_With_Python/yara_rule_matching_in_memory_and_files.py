"""
Yara Rule Matching In Memory And Files

Security operations automation tool.
"""

#
# pip install yara-python
# Ensure that the system YARA library is also installed (on some Linux systems you might
# need `libyara-dev`).
#
# A YARA rule has:
# - A name
# - Strings to match (text, hex, regex)
# - A condition to trigger a match
#
# rule SuspiciousFunction
# {
#     strings:
#         $a = "CreateRemoteThread"
#         $b = "VirtualAllocEx"
#         $c = /malicious_\w{4}/
#
#     condition:
#         2 of them
# }
import yara
# Define YARA rules as string
rules_text = """
rule MalwarePattern
{
    strings:
        $a = "cmd.exe"
        $b = "powershell.exe"
        $hex = { 6A 40 68 00 30 00 00 }  // Common PE shellcode pattern
    condition:
        any of them
}
"""
# Compile the rule into an executable form
rules = yara.compile(source=rules_text)
# - The `source=` argument compiles a YARA rule directly from a Python string.
# - You can also use `filename="rules.yar"` to load from a `.yar` file.
#
def scan_file(filepath, compiled_rules):
    """
    Scan a file using compiled YARA rules.
    """
    matches = compiled_rules.match(filepath)
    return matches
# - `match()` scans the file and returns a list of matches (if any).
# - Each match includes rule name, strings matched, and offsets.
#
if __name__ == "__main__":
    target_file = "suspicious_file.bin"  # Replace with your sample
    try:
        results = scan_file(target_file, rules)
        if results:
            print("[+] Matches found:")
            for match in results:
                print("Rule:", match.rule)
                for s in match.strings:
                    offset, identifier, data = s
                    print(f" - Offset: {offset}, Identifier: {identifier}, Value: {data}")
        else:
            print("[-] No matches.")
    except yara.Error as e:
        print("YARA scanning error:", e)
# If you extract a memory region (e.g., via `volatility`, `psutil`, or from a dump), you
# can scan directly:
def scan_memory_buffer(data, compiled_rules):
    """
    Scan raw memory bytes (e.g., from a dump or process).
    """
    return compiled_rules.match(data=data)
# This is ideal when you've already extracted a memory segment from a process or dump
# and want to scan it inline.
#
# You can compile many rules from a folder or file:
# Compiling rules from a YARA file
compiled = yara.compile(filepath="all_rules.yar")
# Or even multiple files using a dictionary map:
rule_sources = {
    'generic': 'rules/generic.yar',
    'apt': 'rules/apt_rules.yar'
}
compiled = yara.compile(filepaths=rule_sources)
import json
def save_results_to_json(results, output_path="yara_results.json"):
    serializable = []
    for match in results:
        match_dict = {
            "rule": match.rule,
            "meta": match.meta,
            "strings": [
                {"offset": offset, "identifier": ident, "data": str(data)}
                for offset, ident, data in match.strings
            ]
        }
        serializable.append(match_dict)
    with open(output_path, "w") as f:
        json.dump(serializable, f, indent=2)
# - Sanitize user input if loading rule content dynamically.
# - Use precompiled `.yar` files for cleaner organization.
# - Normalize memory buffers (strip nulls, decode as needed).
# - Always handle exceptions (`yara.SyntaxError`, `yara.MatchError`).
# - Run rules in isolated containers for sandboxed detection.
#
def scan_memory_dump_with_yara(dump_path, rules):
    with open(dump_path, "rb") as f:
        data = f.read()
    return scan_memory_buffer(data, rules)
# You can extend this logic to automatically scan multiple dumps or files in batch jobs.
#
# Python and YARA together allow powerful pattern-based scanning of:
# - Memory segments