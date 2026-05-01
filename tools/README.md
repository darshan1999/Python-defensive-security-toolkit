# Security Operations Tools: 114 Production-Ready Utilities

**Complete toolkit for enterprise security operations, detection, and response**

This directory contains 114 production-ready Python tools organized by security function. These tools integrate with the 6 SIEM modules in the `python/` folder and can be deployed independently or as part of a larger security orchestration platform.

---

## 🎯 Tools Overview

**114 Tools** across 6 operational categories:

| Category | Tools | Purpose |
|----------|-------|---------|
| **Asset Discovery & Scanning** | 001-050 | Network reconnaissance, asset inventory, change monitoring |
| **Malware Analysis & Detection** | 051-093 | File analysis, IOC extraction, behavioral detection |
| **Behavioral Detection** | 094-105 | Log analysis, anomaly detection, persistence detection |
| **Reporting & Integration** | 106-114 | Dashboards, exports, SOAR integration |

---

## 📊 Tools by Category

### **Layer 1: Asset Discovery & Scanning (Tools 001-050)**

Network reconnaissance and asset management:

| Tool | Name | Purpose |
|------|------|---------|
| 001 | Domain Information Gatherer | WHOIS, DNS, registration data collection |
| 002 | Port Scanner Basic | Basic TCP port scanning |
| 003 | Port Scanner Advanced | Multi-threaded advanced port scanning |
| 004 | Service Version Detector | Service identification and version detection |
| 005 | Asset Inventory Scanner | Complete asset discovery and cataloging |
| 006 | Change Monitor | Configuration and service change detection |
| 007 | Vulnerability Scope Validator | Validates exposure scope of vulnerabilities |
| 008 | Threat Detection Scanner | Scans for known threat indicators |
| 009 | Honeypot Detector | Identifies honeypot systems |
| 010 | Perimeter Exposure Validator | Validates external exposure |
| 011 | Internal Network Mapper | Maps internal network topology |
| 012 | Security Control Validator | Validates security controls |
| 013 | Lateral Movement Path Checker | Analyzes lateral movement paths |
| 014 | Socket Validation Scanner | Raw socket validation scanning |
| 015 | Service Enumeration Tool | Service enumeration and profiling |
| 016 | Telegram Alert Integration | Sends alerts to Telegram |
| 017 | SQLite Port Scan Database | Stores port scan results in SQLite |
| 018 | Threaded Multi-Port Scanner | Parallel port scanning |
| 019 | IP Geolocation Enricher | Enriches IPs with geolocation |
| 020 | IOC Enrichment Tool | Enriches indicators of compromise |
| 021 | VirusTotal File Uploader | Uploads files to VirusTotal |
| 022 | Hybrid Analysis Integration | Integrates with Hybrid Analysis |
| 023 | Blocklist Checker | Checks IPs/domains against blocklists |
| 024 | Alert Prioritization Engine | Prioritizes alerts by severity |
| 025 | CSV IP Enricher | Batch enriches IPs from CSV |
| 026 | Threat Score Calculator | Calculates threat scores |
| 027 | Rare Country ASN Alerter | Alerts on rare country/ASN connections |
| 028 | SIEM Dashboard Enhancer | Enhances SIEM dashboards |
| 029 | File Integrity Monitor | Monitors file integrity changes |
| 030 | Web Shell Detector | Detects web shell artifacts |
| 031 | Ransomware Activity Monitor | Monitors for ransomware indicators |
| 032 | After-Hours Change Monitor | Tracks changes outside business hours |
| 033 | Persistence Detection Tool | Detects persistence mechanisms |
| 034 | Data Exfiltration Tracker | Tracks data exfiltration attempts |
| 035 | Web Shell Hunter | Hunts for web shell implementations |
| 036 | SHA256 Baseline Creator | Creates file integrity baselines |
| 037 | Baseline Comparison Tool | Compares against baselines |
| 038 | Real-Time Watchdog Monitor | Real-time file system monitoring |
| 039 | File Size Threshold Alerter | Alerts on unusual file sizes |
| 040 | File Owner/Group Tracker | Tracks file ownership changes |
| 041 | Scheduled File Monitor | Monitors files on schedule |
| 042 | /var/www Monitor | Monitors web server directories |
| 043 | PHP EXE Creation Alerter | Alerts on PHP/EXE creation |
| 044 | Firewall Log Analyzer | Analyzes firewall logs |
| 045 | Top Offenders Reporter | Reports top threat sources |
| 046 | Multi-Format Exporter | Exports data in multiple formats |
| 047 | Threshold Warning Logger | Logs threshold violations |
| 048 | SSH Login Parser | Parses SSH login attempts |
| 049 | Failed Login Counter | Counts failed login attempts |
| 050 | Brute Force Detector | Detects brute force attacks |

---

### **Layer 2: Malware Analysis & IOC Detection (Tools 051-093)**

File analysis and indicator extraction:

| Tool | Name | Purpose |
|------|------|---------|
| 051 | Malware Behavior Analyzer | Analyzes malware behavior patterns |
| 052 | Suspicious Activity Logger | Logs suspicious activities |
| 053 | Artifact Extractor | Extracts forensic artifacts |
| 054 | Hash Calculator | Computes file hashes (MD5, SHA1, SHA256) |
| 055 | File Type Identifier | Identifies file types |
| ... | ... | ... |
| 093 | Memory Dump Scanner | Scans memory dumps for artifacts |

---

### **Layer 3: Behavioral Detection & Forensics (Tools 094-105)**

Advanced detection and analysis:

| Tool | Name | Purpose |
|------|------|---------|
| 094 | Anomaly Detector | Detects statistical anomalies |
| 095 | Timeline Reconstructor | Rebuilds incident timelines |
| 096 | Registry Parser | Parses Windows registry |
| 097 | Event Log Analyzer | Analyzes Windows event logs |
| 098 | Process Tree Analyzer | Analyzes process execution trees |
| 099 | Network Connection Tracker | Tracks network connections |
| 100 | DNS Query Analyzer | Analyzes DNS queries |
| 101 | HTTP Traffic Analyzer | Analyzes HTTP traffic |
| 102 | Scheduled Task Tracker | Tracks scheduled tasks |
| 103 | Driver Analyzer | Analyzes driver loads |
| 104 | Persistence Mechanism Finder | Finds persistence mechanisms |
| 105 | Lateral Movement Detector | Detects lateral movement |

---

### **Layer 4: Reporting & Integration (Tools 106-114)**

Dashboards, exports, and orchestration:

| Tool | Name | Purpose |
|------|------|---------|
| 106 | Executive Dashboard Generator | Generates executive dashboards |
| 107 | Scheduled Task Runner | Runs security tools on schedule |
| 108 | Splunk Event Sender | Sends events to Splunk |
| 109 | Elasticsearch Bulk Loader | Loads events into Elasticsearch |
| 110 | PagerDuty Alert Router | Routes alerts to PagerDuty |
| 111 | Slack Notification Sender | Sends notifications to Slack |
| 112 | SOAR Workflow Executor | Executes SOAR workflows |
| 113 | Automated Report Generator | Generates automated reports |
| 114 | Configuration Manager | Manages tool configurations |

---

## 🚀 Tool Integration with SIEM Modules

Each tool integrates with one or more SIEM modules:

```
Tools 001-050  →  Module 01: Security Automation
                   Asset discovery, scanning, monitoring

Tools 051-093  →  Module 04: Malware Analysis
                   File analysis, IOC extraction

Tools 094-105  →  Module 02: SOC Analysis
                   Behavioral detection, correlation

Tools 106-114  →  Module 05: Detection Engineering
                   Orchestration, dashboards, SOAR
```

---

## 📋 Common Tool Patterns

### Discovery Tools (001-015)
- Enumerate network assets
- Identify services and versions
- Build inventory databases
- Alert on changes

**Usage**: Run continuously or on schedule
```bash
python 005_asset_inventory_scanner/scanner.py
```

### Analysis Tools (051-093)
- Analyze files and memory
- Extract IOCs (IPs, domains, hashes)
- Generate YARA rules
- Score threats

**Usage**: Run on detected files
```bash
python 054_hash_calculator/hasher.py /path/to/file
```

### Detection Tools (094-105)
- Monitor logs for anomalies
- Track behavioral patterns
- Reconstruct timelines
- Find persistence

**Usage**: Deploy as agents or scheduled jobs
```bash
python 094_anomaly_detector/detector.py --log-file security.log
```

### Reporting Tools (106-114)
- Generate dashboards
- Send alerts
- Export data
- Execute workflows

**Usage**: Triggered by other tools
```bash
python 112_soar_workflow_executor/executor.py --workflow incident_response
```

---

## 🔧 Tool Dependencies

Most tools require:
- Python 3.7+
- Standard libraries (os, sys, json, etc.)
- Optional: requests, paramiko, yara-python, volatility, etc.

**Install all requirements**:
```bash
for dir in */; do pip install -r "$dir/requirements.txt" 2>/dev/null; done
```

---

## 📊 Tool Statistics

- **Total tools**: 114
- **Asset discovery**: 50 tools
- **Malware analysis**: 43 tools
- **Behavioral detection**: 12 tools
- **Reporting & integration**: 9 tools

---

## 🎯 Use Cases

### Incident Response
- Tools 051-093: Analyze suspicious file
- Tools 094-105: Detect in logs
- Tools 106-114: Generate report and alert

### Threat Hunting
- Tools 001-050: Scan for indicators
- Tools 094-105: Correlate events
- Tools 106-114: Export and present findings

### Continuous Monitoring
- Tools 001-050: Scan assets on schedule
- Tools 094-105: Monitor for anomalies
- Tools 106-114: Alert on findings

### Risk Assessment
- Tools 001-050: Enumerate exposure
- Tools 026: Calculate threat scores
- Tools 106-114: Generate executive summary

---

## 🔄 Example Workflows

### Threat Detection Workflow
1. **Tool 023** - Check IP against blocklist
2. **Tool 019** - Enrich with geolocation
3. **Tool 026** - Calculate threat score
4. **Tool 024** - Prioritize alert
5. **Tool 111** - Send Slack notification
6. **Tool 113** - Generate incident report

### Malware Analysis Workflow
1. **Tool 054** - Hash file
2. **Tool 021** - Check VirusTotal
3. **Tool 022** - Submit to Hybrid Analysis
4. **Tool 051** - Analyze behavior
5. **Tools 053, 055-093** - Extract IOCs
6. **Tool 113** - Generate analysis report

### Asset Discovery Workflow
1. **Tool 005** - Scan network
2. **Tool 019** - Enrich IPs
3. **Tool 006** - Monitor changes
4. **Tool 007** - Validate exposure
5. **Tool 028** - Enhance dashboard
6. **Tool 113** - Report findings

---

## 📖 Tool Documentation

Each tool directory contains:
- `README.md` - Tool purpose and usage
- `tool.py` or main script - Implementation
- `requirements.txt` - Dependencies
- Example configuration files where applicable

---

## 🚀 Deployment Options

### Standalone
```bash
python tool.py [arguments]
```

### Scheduled
```bash
# Add to crontab for continuous execution
0 */6 * * * /usr/bin/python3 /path/to/tool.py
```

### Docker
```dockerfile
FROM python:3.9
RUN pip install -r requirements.txt
CMD ["python", "tool.py"]
```

### SIEM Integration
```python
# Send output to SIEM
import subprocess
result = subprocess.run(['python', 'tool.py'], capture_output=True)
siem.send_event(result.stdout)
```

---

## 🔒 Security Considerations

- **API Credentials**: Store in environment variables, not in code
- **Rate Limiting**: Respect API quotas and rate limits
- **Error Handling**: Graceful degradation if APIs fail
- **Logging**: Log all tool executions for audit trail
- **Permissions**: Run with minimal required privileges

---

## 🎯 Tool Categories Reference

**Quick lookup by function**:

- **Scanning**: 002, 003, 005, 011, 014, 018
- **Monitoring**: 006, 029, 032, 038, 041, 042
- **Analysis**: 054-093 (file, memory, behavior)
- **Enrichment**: 019, 020, 025, 026
- **Detection**: 030, 031, 033, 034, 035, 050, 094-105
- **Reporting**: 046, 106, 109, 113
- **Integration**: 016, 108, 109, 110, 111, 112

---

## 🤝 Integration Points

Tools connect via:
- **File I/O** - Read/write results
- **Databases** - SQLite, MySQL, etc.
- **APIs** - REST, TAXII, STIX
- **Message Queues** - For event streaming
- **SIEM Platforms** - Splunk, ELK, Sumologic

---

**Ready to deploy?** Start with tools in Layer 1 for discovery, then add Layer 2 analysis as needed.

