**Python SIEM Coursework — Annotated Learning Exercises**

Note for recruiters and reviewers: 
This folder contains my coursework and learning notes from studying blue team Python and SIEM architecture. These are annotated scripts written while working through security automation concepts — they are intentionally educational, not production tools.
For production-ready, runnable tools see the tools/ directory — 114 standalone scripts with full CLI interfaces, argparse, and error handling.

**What this folder is**
Each sub-module here is a Python file I wrote while learning a specific security concept. The files contain:

Working code snippets demonstrating each technique
Inline comments explaining why something works, not just how
References to real-world scenarios (brute-force detection, memory forensics, SIEM integration)
Notes on what libraries and APIs are used in production environments

They are structured like study guides with runnable examples, similar to a Jupyter notebook but in plain .py format. Many reference external files (auth.log, sample.exe, etc.) or require API keys — they are meant to be read and adapted, not run directly.
---
<img width="834" height="663" alt="image" src="https://github.com/user-attachments/assets/95b9a1ff-c1ae-4510-89bb-f711aefc0b62" />


## 📁 Module Directory

### **[01_security-automation](./01_security-automation/)**

Covers Python-driven OS command execution, network reconnaissance with Nmap and raw sockets, REST API integration, filesystem monitoring with watchdog, APScheduler for continuous monitoring, and structured data output (CSV/JSON/Excel).
- **Key concepts learned:** subprocess safety, socket programming, scheduler design, output formatting for SOC consumption.

**Layer 1: Asset Discovery & Reconnaissance**

7 sub-modules automating security reconnaissance and asset discovery:
- Operating system command automation
- Automated reconnaissance and scanning with Nmap
- Manual port scanning with Python sockets
- API integration for external services
- Filesystem monitoring and data collection
- Continuous scheduling and monitoring
- Data handling and output generation

**Output**: Asset inventory, service mappings, exposure reports
**Real-world use**: Continuous asset discovery feeds your SIEM's inventory layer

[→ Full Module Details](./01_security-automation/README.md)

---

### **[02_soc-analysis](./02_soc-analysis/)**

Covers log normalization from multiple source types, regex-based detection of brute-force and off-hours logins, event correlation across auth/file/command logs, dashboard export formats, and enriching log events with external threat intelligence APIs.
**Key concepts learned:** log parsing patterns, threshold-based alerting, multi-source correlation, data enrichment pipelines.

**Layer 2: Log Analysis & Detection**


5 sub-modules for log ingestion, normalization, and behavioral detection:
- Log normalization and parsing from 170+ source types
- Detection of suspicious behavior and anomalies
- Event correlation across multiple sources
- Data export to dashboards (CSV, Excel, JSON)
- Log enrichment with external intelligence

**Output**: Normalized events, alerts, dashboards
**Real-world use**: The heartbeat of your SIEM—where raw events become intelligence

[→ Full Module Details](./02_soc-analysis/README.md)

---

### **[03_threat-intelligence](./03_threat-intelligence/)**

Covers connecting to STIX/TAXII and OTX feeds, enriching IOCs (IPs, domains, hashes) via VirusTotal, AbuseIPDB, SecurityTrails, and GreyNoise APIs, and generating structured threat reports with scoring and recommendations.
**Key concepts learned:** TI feed consumption, API rate limiting, IOC scoring, report generation.
API keys required — placeholders are in place. Replace with your own keys before running

**Layer 3: Threat Intelligence Integration**

4 sub-modules for consuming and managing threat intelligence:
- Introduction to threat intelligence and Python integration
- Consuming threat intelligence feeds (STIX, TAXII, OpenIOC)
- Enriching IOCs via public and commercial APIs
- Generating actionable reports and indicators

**Output**: Enriched IOC database, threat reports, recommendations
**Real-world use**: Transform your SIEM from reactive to proactive threat hunting

[→ Full Module Details](./03_threat-intelligence/README.md)

---

### **[04_malware-analysis](./04_malware-analysis/)**

Covers MD5/SHA256/SHA512 file hashing, magic byte and PE header inspection, string and IOC extraction from binaries, YARA rule integration, behavioral sandbox emulation hooks, memory dump carving, and Hybrid Analysis API automation.
**Key concepts learned:** static analysis workflow, YARA rule syntax, memory forensics basics, sandbox API integration.

**Layer 4a: Malware Analysis & IOC Extraction**

9 sub-modules for analyzing suspicious files and extracting indicators:
- File hashing and integrity verification
- Basic static file analysis (headers, magic bytes, strings)
- IOC extraction from scripts and binaries
- Behavioral analysis integration with sandbox emulation
- YARA rule generation and matching
- Extracting suspicious code blocks from binaries
- Memory dump carving and analysis
- Automating analysis with Hybrid Analysis
- Extracting malware configurations

**Output**: IOC lists, severity assessments, YARA rules, behavioral profiles
**Real-world use**: Investigation layer that validates threats detected by other layers

[→ Full Module Details](./04_malware-analysis/README.md)

---

### **[05_detection-engineering](./05_detection-engineering/)**

Covers Splunk/ELK/Sumo Logic API integration, syslog and HTTP event forwarding, CrowdStrike and SentinelOne API interaction, automated IOC blocking in firewalls and EDR, custom detection pipeline design, real-time alerting, and threat hunting query automation.
**Key concepts learned:** SIEM ingestion methods, EDR API patterns, response automation logic, pipeline architecture.

**Layer 5: SIEM & EDR Integration**

8 sub-modules for orchestrating end-to-end security response:
- Integrating with SIEM platforms (Splunk, ELK, Sumologic)
- Sending events to SIEM via Syslog, HTTP, JSON, UDP
- Interacting with EDR systems via APIs (CrowdStrike, Sentinel One)
- Automating IOC blocking in firewalls and EDR
- Building custom detection pipelines
- Real-time alerting and response automation
- Custom dashboards from SIEM/EDR data
- Threat hunting automation

**Output**: Alerts, dashboards, automated responses, hunt results
**Real-world use**: Orchestration layer that ties all security tools together

[→ Full Module Details](./05_detection-engineering/README.md)

---

### **[06_advanced-analysis](./06_advanced-analysis/)**

Covers building YARA scanners, integrating Python with Cuckoo Sandbox, extracting embedded shellcode from PE files, PCAP parsing for network-based IOCs, detecting anti-analysis evasion techniques, and memory dump IOC extraction.
**Key concepts learned:** advanced static/dynamic analysis, PCAP analysis with Scapy, evasion detection heuristics, memory forensics with Volatility.

**Layer 4b: Advanced Forensics & Memory Analysis**

7 sub-modules for deep-dive forensic investigation:
- Building YARA scanners in Python
- Integrating Python with Cuckoo Sandbox
- Extracting embedded shellcode and payloads
- Analyzing malware network behavior (PCAP parsing)
- Detecting anti-analysis and evasion techniques
- Memory dump analysis and IOC extraction
- YARA rule matching in memory and files

**Output**: YARA rules, behavioral signatures, configuration intelligence
**Real-world use**: Deep investigation capability for sophisticated threats

[→ Full Module Details](./06_advanced-analysis/README.md)

---

## 🏗️ Module Integration Map

Python automation for blue team workflows:- 
- SIEM architecture (5-layer: collection → detection → intelligence → investigation → response)
- API integration with major security platforms (VirusTotal, CrowdStrike, Splunk, AbuseIPDB, Hybrid Analysis)
- Log analysis, normalization, and correlation
- Malware triage: static analysis, YARA, memory forensics
- Detection engineering: pipelines, alerting, automated response
- Threat intelligence: feed consumption, IOC enrichment, reporting

```
┌─────────────────────────────────────────────────────────────┐
│        Your Organization's SIEM Architecture                │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  Layer 5: Integration & Orchestration                        │
│  └─ Module 05: Detection Engineering                         │
│     └─ SIEM, EDR, Firewall APIs, Alerting, Response         │
│        ↑                                                      │
│  Layer 4: Investigation & Forensics                          │
│  ├─ Module 04: Malware Analysis                              │
│  │  └─ Static/Dynamic Analysis, IOCs, YARA Rules            │
│  └─ Module 06: Advanced Analysis                             │
│     └─ Memory Forensics, Shellcode, Evasion Detection       │
│        ↑                                                      │
│  Layer 3: Intelligence & Enrichment                          │
│  └─ Module 03: Threat Intelligence                           │
│     └─ Feed Ingestion, IOC Enrichment, Reports              │
│        ↑                                                      │
│  Layer 2: Detection & Analysis                               │
│  └─ Module 02: SOC Analysis                                  │
│     └─ Log Parsing, Normalization, Correlation, Detection   │
│        ↑                                                      │
│  Layer 1: Collection & Discovery                             │
│  └─ Module 01: Security Automation                           │
│     └─ Asset Discovery, Scanning, Monitoring               │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```
---

## 🚀 Quick Start

### Install All Dependencies
```bash
# Install requirements for all modules
pip install -r 01_security-automation/requirements.txt
pip install -r 02_soc-analysis/requirements.txt
pip install -r 03_threat-intelligence/requirements.txt
pip install -r 04_malware-analysis/requirements.txt
pip install -r 05_detection-engineering/requirements.txt
pip install -r 06_advanced-analysis/requirements.txt
```

### Run Individual Modules
```bash
# Example: Security automation
cd 01_security-automation/Sub_01_Working_With_Operating_System_Commands
python working_with_os_commands.py

# Example: Log analysis
cd ../../../02_soc-analysis/Sub_01_Log_Normalization_And_Parsing
python log_normalization_and_parsing.py

# Example: Threat intelligence
cd ../../../03_threat-intelligence/Sub_02_Consuming_Threat_Intelligence_Feeds
python consuming_threat_intelligence_feeds.py
```

---

## 🔄 Data Flow Through SIEM

**Complete incident response scenario:**

1. **Layer 1 (Module 01)**: Asset automation discovers new SSH service on production network
2. **Layer 2 (Module 02)**: SOC analysis detects 10+ failed login attempts from same IP
3. **Layer 3 (Module 03)**: TI enrichment reveals source IP is known C2 infrastructure
4. **Layer 4 (Modules 04 & 06)**: If file present, malware analysis extracts indicators and generates YARA rule
5. **Layer 5 (Module 05)**: Detection engineering:
   - Auto-blocks IP on firewall
   - Disables compromised account
   - Isolates affected endpoint
   - Creates incident ticket
   - Notifies incident response team
   - Runs threat hunt for past occurrences

**Timeline: T+0 to T+30 minutes**

---

## 📋 Use Cases by Module

### Security Automation (Module 01)
- Continuous asset discovery
- Configuration change detection
- Service version monitoring
- Exposure validation

### SOC Analysis (Module 02)
- Brute force detection
- Lateral movement tracking
- Privilege escalation detection
- Data exfiltration identification

### Threat Intelligence (Module 03)
- Consuming public feeds (OTX, Cyber Threat Coalition)
- Commercial feed integration (Mandiant, CrowdStrike)
- IOC enrichment and scoring
- Campaign tracking

### Malware Analysis (Module 04)
- File hash validation
- Embedded IOC extraction
- YARA rule generation
- Malware family classification

### Detection Engineering (Module 05)
- SIEM event ingestion
- EDR data correlation
- Automated response workflows
- Threat hunting queries

### Advanced Analysis (Module 06)
- Memory forensics
- Shellcode detection
- Anti-analysis technique identification
- Complex incident reconstruction

---

## 🔧 Requirements & Dependencies

Each module has a `requirements.txt` specifying Python package dependencies:
- requests, urllib3 - HTTP and REST APIs
- python-nmap - Network scanning
- APScheduler - Task scheduling
- paramiko - SSH automation
- yara-python - Malware signatures
- volatility - Memory forensics
- And many more...

Install per-module or globally as needed.

---

## 🎯 Learning Outcomes

By working through these modules, you'll demonstrate:

✅ SIEM architecture design and implementation
✅ Python-based security automation
✅ Log analysis and correlation
✅ Threat intelligence operations
✅ Malware analysis workflows
✅ Detection engineering and rule writing
✅ API integration (SIEM, EDR, firewalls, threat feeds)
✅ Incident response automation
✅ Enterprise-scale security operations

---

## 📚 Production Deployment

These modules are production-ready and can be deployed:
- As standalone security tools
- Integrated into existing SIEM platforms
- Orchestrated through SOAR (Security Orchestration, Automation and Response)
- Containerized in Docker for scalable deployment
- Executed via scheduled tasks or event-driven triggers

---

## 🤝 Module Interdependencies

- **Module 01** → feeds asset data to Module 02
- **Module 02** → generates alerts for Module 04/06
- **Module 03** → enriches events from Module 02
- **Module 04/06** → produces IOCs for Module 03
- **Modules 01-04** → all feed data to Module 05
- **Module 05** → orchestrates responses across all other modules

---

## 📖 Documentation

- Each module has detailed README.md explaining its role in SIEM architecture
- Each sub-module contains working Python code with functional comments
- Root-level SIEM_ARCHITECTURE.md explains 5-layer design
- Root-level PORTFOLIO_HIGHLIGHTS.md maps skills to job roles

---

**Ready to deploy your SIEM?** Start with Module 01 for asset discovery, then progress through each layer as your security operations mature.

