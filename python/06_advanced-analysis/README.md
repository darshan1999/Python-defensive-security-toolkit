# Advanced Analysis: Forensics, Memory Analysis & YARA Rules

**Part of the SIEM Architecture** | Layer 4b: Advanced Detection & Investigation

## Overview
This module teaches advanced forensics and malware analysis techniques. Extract embedded payloads and shellcode, detect anti-analysis tricks, memory forensics, and generate YARA rules for signature-based detection across your SIEM. This is the deep-dive layer for complex incidents that simple detection misses.

## Why This Matters for Your SIEM
When simple indicators fail, advanced techniques succeed:
- **Memory forensics** - Detect fileless malware (no signatures)
- **Shellcode extraction** - Understand injected code and payloads
- **Anti-analysis detection** - Identify evasion techniques
- **YARA rules** - Create powerful multi-condition detection signatures
- **Complex incident reconstruction** - Build complete attack timelines

This module handles your hardest cases—the sophisticated adversaries who stay in memory.

## Key Topics

### 1. Extracting Embedded Shellcode & Payloads
Analyze injected code:
- Identify shellcode in binaries and memory
- Extract embedded payloads from scripts
- Decode obfuscated code
- Analyze decoded instructions for IOCs
- Generate behavior signatures

**Real-world application**: APT malware injects shellcode to avoid detection—you extract it.

### 2. Detecting Anti-Analysis & Evasion Techniques
Identify attacker tricks:
- Virtual machine detection checks
- Debugger detection
- User-mode hooks
- Inline code patching
- API call interception
- Timing-based analysis

**Real-world application**: Confirm malware behavior even when it tries to hide.

### 3. Memory Dump Carving
Extract artifacts from memory:
- Identify malware in memory that's not on disk
- Extract configuration blocks
- Reconstruct command execution history
- Find injected code regions
- Extract encryption keys and credentials

**Real-world application**: Rootkits and fileless malware live in memory.

### 4. Integrating YARA for Signature Detection
Create powerful detection rules:
- Write YARA rules for malware families
- Match file contents, metadata, behavior signatures
- Create rule sets for your SIEM
- Integrate with detection pipelines
- Match against sample repositories

**Real-world application**: Deploy rule set across endpoints, detect all variants instantly.

### 5. YARA Rule Matching In-Memory & Files
Continuous scanning:
- Scan running processes
- Monitor file system changes
- Real-time rule application
- Rule performance optimization
- False positive tuning

**Real-world application**: Your SIEM continuously looks for bad patterns.

### 6. Extracting Malware Configurations
Understand malware intent:
- Parse C2 addresses from config blocks
- Extract credentials and tokens
- Identify target systems or environments
- Find campaign identifiers
- Understand capabilities and options

**Real-world application**: Ransomware config tells you who they're targeting.

## Tools Included
- **Shellcode extractors**: Identify and extract injected code
- **Evasion detectors**: Anti-VM, anti-debug, anti-analysis detection
- **Memory forensics**: Dump analysis, artifact extraction
- **YARA rule generators**: Auto-generate rules from samples
- **Rule engines**: YARA runtime integration, matching optimization
- **Malware config extractors**: Parse command & control, campaign metadata
- **Behavior analyzers**: Connect TTPs to MITRE ATT&CK framework

## Setup & Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Extract shellcode
python using_python_to_extract_embedded_shellcode_or_payloads_from_binaries.py

# Detect evasion
python detecting_anti_analysis_and_evasion_techniques_in_malware_using_python.py

# Memory carving
python memory_dump_carving.py

# Generate YARA rules
python yara_rule_generation_from_malware_samples.py

# Apply rules
python yara_rule_matching_in_memory_and_files_with_python.py

# Extract configs
python extracting_malware_configs.py
```

## Connection to SIEM
- **Inputs**: Suspicious samples, memory dumps, incident forensics
- **Outputs**: YARA rules, behavioral signatures, configuration intelligence
- **Feeds**: Detection engines (all systems), threat intelligence database, hunt queries
- **Example**: 
  1. EDR detects file creation anomaly (unknown binary in system32)
  2. File uploaded for analysis
  3. Detected as fileless malware (needs memory analysis)
  4. Memory extracted, shellcode analyzed
  5. YARA rule auto-generated from extracted code
  6. Rule deployed across 5000 endpoints in 30 minutes
  7. Detect 47 additional infected systems before they act

## Production Considerations
- **Analysis safety**: Use isolated analysis environments
- **Tool compatibility**: YARA versions, library dependencies
- **Performance**: Memory dumps can be GB-sized; optimize parsing
- **False positives**: Overly broad YARA rules cause alert fatigue
- **Documentation**: Document complex rules for team understanding
- **Testing**: Validate rules against known malware and benign samples

## Advanced Techniques Covered
- Static analysis combined with dynamic behavior
- Cross-platform analysis (Windows, Linux, MacOS)
- Packed and obfuscated code analysis
- Multi-stage payload detection
- Campaign attribution and clustering
- TTPs mapping (MITRE ATT&CK)

## Files in This Module
```
06_advanced-analysis/
├── Sub_*/ (topic-specific subdirectories)
│   ├── *.py (implementation examples)
│   └── README.md (topic details)
└── README.md (this file)
```
