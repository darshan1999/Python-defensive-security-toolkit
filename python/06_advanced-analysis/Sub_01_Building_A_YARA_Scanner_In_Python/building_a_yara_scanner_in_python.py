"""
Building A Yara Scanner In Python

Security operations automation tool.
"""

#
# pip install yara-python
# Or, if you need to build from source:
#
# git clone https://github.com/VirusTotal/yara
# cd yara
# ./bootstrap.sh && ./configure && make && sudo make install
# pip install yara-python
# Let's write a simple YARA rule that detects a known signature (like a string or hex
# pattern):
#
# rule SuspiciousExecutable
# {
#     meta:
#         description = "Detects EXE files with suspicious imports"
#         author = "Analyst"
#         threat_level = 3
#
#     strings:
#         $a = "VirtualAlloc"
#         $b = "LoadLibrary"
#         $c = { 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? }
#
#     condition:
#         2 of ($a,$b,$c)
# }
# Save this rule in a file like `rules.yar`.
#
# ## 4. Loading and Compiling YARA Rules in Python
import yara
# Compile the rule file into memory
rules = yara.compile(filepath='rules.yar')
# Load and scan a file (e.g., a malware sample)
matches = rules.match('suspect.exe')
# Print out the matched rule names and metadata
for match in matches:
    print(f"[+] Rule matched: {match.rule}")
    for name, value in match.meta.items():
        print(f"    {name}: {value}")
# 🔍 Note: You can also compile from string using `yara.compile(source=...)`.
#
# ## 5. Handling Rule Matches Programmatically
# YARA results can be parsed and used to trigger alerts, store indicators, or classify
# samples.
def analyze_yara_output(matches):
    result = {}
    for match in matches:
        result[match.rule] = {
            "meta": match.meta,
            "strings_matched": [s[1] for s in match.strings],
        }
    return result
summary = analyze_yara_output(matches)
print(summary)
# This approach allows you to log or forward structured information to SIEMs or
# dashboards.
#
# ## 6. Scanning In-Memory Data
# You can scan memory buffers (like extracted config sections or decrypted payloads):
buffer_data = b"This contains VirtualAlloc and LoadLibrary and some shellcode..."
matches = rules.match(data=buffer_data)
for match in matches:
    print(f"Match in buffer: {match.rule}")
# Useful for sandboxing, unpacked payloads, or dynamic analysis outputs.
#
# ## 7. Compiling Multiple Rule Files and Rule Sets
rules = yara.compile(filepaths={
    'shellcode_rules': 'shellcode.yar',
    'persistence_rules': 'persistence.yar',
    'obfuscation_rules': 'obfuscation.yar'
})
# This lets you maintain modular, targeted rulebases by category.
#
# ## 8. Creating Dynamic Rules in Python
# If you're building signatures dynamically:
rule_template = '''
rule DynamicDomainRule {{
    meta:
        source = "ThreatFeed"
    strings:
        $domain = "{domain}"
    condition:
        $domain
}}
'''
# Dynamically build rule for a domain
new_rule = rule_template.format(domain="malicious-site.com")
rules = yara.compile(source=new_rule)
matches = rules.match(data=b"Connecting to malicious-site.com ...")
for m in matches:
    print(f"[Dynamic] Matched rule: {m.rule}")
# Great for IOC feeds or real-time alert enrichment.
#
# ## 9. Error Handling with Invalid Rules
try:
    rules = yara.compile(filepath="broken_rules.yar")
except yara.SyntaxError as e:
    print("YARA syntax error:", e)
# Always validate rules before loading, especially if sourced from external systems or
# feeds.
#
# ## 10. Integration Use Cases
#
# ## 11. Outputting Results to JSON/CSV
import json
results = analyze_yara_output(matches)
with open("yara_results.json", "w") as f:
    json.dump(results, f, indent=2)
# Or CSV:
import csv
with open("yara_matches.csv", "w", newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["Rule", "Matched Strings"])
    for match in matches:
        strings = ','.join([s[1] for s in match.strings])
        writer.writerow([match.rule, strings])