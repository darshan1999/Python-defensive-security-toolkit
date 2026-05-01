# 🛡️ Defensive Security Portfolio

**Complete end-to-end security automation and threat detection framework**

This repository contains a comprehensive defensive security portfolio combining 114 production-ready tools with 6 SIEM implementation modules. It's designed for security professionals, SOC analysts, and defenders working in enterprise environments.

---

## 📋 Portfolio Structure

```
python_defensive_security_portfolio/
├── tools/                    # 114 production-ready security tools
│   ├── 001-050/             # Asset Discovery & Network Scanning
│   ├── 051-093/             # Malware Analysis & IOC Detection
│   ├── 094-105/             # Behavioral Detection & Forensics
│   └── 106-114/             # Reporting & Integration
│
├── python/                  # 6 SIEM Implementation Modules
│   ├── 01_security-automation/    # Asset discovery & reconnaissance
│   ├── 02_soc-analysis/           # Log analysis & detection
│   ├── 03_threat-intelligence/    # TI integration & enrichment
│   ├── 04_malware-analysis/       # File analysis & IOCs
│   ├── 05_detection-engineering/  # SIEM orchestration & response
│   └── 06_advanced-analysis/      # Forensics & memory analysis
│
└── README.md, .gitignore    # This file and Python excludes
```

---

## 🚀 Quick Start

### Install & Test
```bash
# Navigate to tools directory
cd tools

# Test a tool
python3 023_blocklist_checker/blocklist_checker.py --help

# Run with sample data
python3 023_blocklist_checker/blocklist_checker.py --create-sample
python3 023_blocklist_checker/blocklist_checker.py 8.8.8.8 --blocklist blocklist.txt

# Test behavioral detection
python3 096_process_monitor/process_monitor.py
python3 098_network_monitor/network_monitor.py

# Test report generation
python3 104_json_behavior_report_generator/json_behavior_report_generator.py --help
```

### Install Python Modules
```bash
# Install core SIEM modules
cd python
pip install -r 01_security-automation/requirements.txt
pip install -r 02_soc-analysis/requirements.txt
pip install -r 03_threat-intelligence/requirements.txt
pip install -r 04_malware-analysis/requirements.txt
pip install -r 05_detection-engineering/requirements.txt
```

---

## 🎯 114 Security Tools Overview

### **Layer 1: Asset Discovery & Scanning (Tools 001-050)**
Network reconnaissance, port scanning, service discovery, asset inventory

**Key Tools:**
- 001-018: Port scanning, service detection, asset mapping, threat scanning
- 019-030: IP geolocation, IOC enrichment, blocklist checking, alert prioritization
- 031-050: File integrity monitoring, ransomware detection, log analysis foundations

**Use Case:** Continuous asset discovery feeds vulnerability management and SIEM inventory

### **Layer 2: Malware Analysis & IOC Detection (Tools 051-093)**
File analysis, string extraction, hash calculation, IOC detection

**Key Tools:**
- 062-077: Hash calculation, file entropy, string analysis, YARA rule generation
- 078-093: Multi-format IOC export (STIX, OpenIOC, MISP), email/registry extraction

**Use Case:** Automated malware triage and indicator extraction for threat hunting

### **Layer 3: Behavioral Detection & Forensics (Tools 094-105)**
Runtime monitoring, persistence detection, baseline comparison

**Key Tools:**
- 094-100: Process/registry/network/filesystem monitoring, DLL hijacking detection
- 101-105: Service detection, scheduled task detection, auto-start extension detection

**Use Case:** EDR-style behavioral analysis deployed on endpoints

### **Layer 4: Reporting & Integration (Tools 106-114)**
Dashboards, scheduled execution, configuration management

**Key Tools:**
- 106-112: Multi-format report generation, task scheduling, exception handling
- 113-114: Service packaging, configuration management

**Use Case:** Orchestration layer connecting all security operations

---


## 📊 Code Quality & Standards

All 114 tools meet strict production standards:

✅ **Real Functional Logic** - No simulation or fake data (except sample generation)
✅ **Standard Library Only** - Uses only Python standard library (no external dependencies)
✅ **Proper Error Handling** - Specific exceptions (FileNotFoundError, ValueError), never bare except
✅ **Professional CLI** - argparse with descriptive --help on every tool
✅ **Analyst-Ready Output** - Tables, JSON, CSV, formatted text optimized for SOC use
✅ **Cross-Platform** - Graceful degradation on non-Windows systems
✅ **Security-Focused** - No hardcoded credentials, safe file operations, input validation

---

## 🔄 Integration Architecture

```
┌─────────────────────────────────────────────────────┐
│     Your Organization's Complete Defense Layer     │
├─────────────────────────────────────────────────────┤
│                                                      │
│  Layer 5: SOAR & Orchestration                      │
│  └─ Tools 106-114: Scheduling, reporting, SIEM     │
│                    ↑                                 │
│  Layer 4: Investigation & Analysis                  │
│  ├─ Tools 051-093: Malware analysis, IOC extraction│
│  └─ Tools 094-105: Behavioral monitoring           │
│                    ↑                                 │
│  Layer 3: Intelligence & Correlation                │
│  └─ Tools 019-050: Threat intel, blocklists        │
│                    ↑                                 │
│  Layer 2: Detection & Response                      │
│  └─ Tools 008-018: Threat scanning, honeypots      │
│                    ↑                                 │
│  Layer 1: Collection & Discovery                    │
│  └─ Tools 001-007: Reconnaissance, scanning        │
│                                                      │
└─────────────────────────────────────────────────────┘
```

---

## 🎓 Learning Paths

### For **SOC Analysts**
Start with: Tools 096-098 (behavioral monitoring) → 031-050 (log analysis) → 104 (reporting)

### For **Incident Responders**
Start with: Tools 062-089 (malware analysis) → 090-105 (IOC extraction) → 046 (export formats)

### For **Threat Hunters**
Start with: Tools 019-050 (threat intel) → 053-089 (correlation) → 104 (report generation)

### For **Security Engineers**
Start with: Tools 001-018 (asset discovery) → 008-015 (controls validation) → 107-114 (orchestration)

---

## 🔗 Python SIEM Modules

The `python/` directory contains 40 sub-modules implementing a complete SIEM system:

| Module | Focus | Use Case |
|--------|-------|----------|
| 01_security-automation | Asset discovery & reconnaissance | Continuous network mapping |
| 02_soc-analysis | Log analysis & detection | Brute force, lateral movement, exfiltration |
| 03_threat-intelligence | TI integration & IOC enrichment | Campaign tracking, reputation scoring |
| 04_malware-analysis | File analysis & extraction | Malware triage, sample classification |
| 05_detection-engineering | SIEM orchestration & response | Automated response workflows |
| 06_advanced-analysis | Forensics & memory analysis | Deep incident investigation |

Each module includes:
- Working Python code with functional comments
- Real API integrations (VirusTotal, Hybrid Analysis, etc.)
- Production-ready error handling
- Comprehensive documentation

---

## 📈 Use Cases

### Continuous Monitoring
Deploy tools 001-018 for asset discovery and 031-050 for log analysis in 24/7 monitoring loops

### Incident Response
Use tools 062-093 for rapid malware analysis and 104 for structured incident reports

### Threat Hunting
Combine tools 019-050 (intel enrichment) with 053-089 (IOC correlation) for proactive hunting

### Vulnerability Management
Leverage tools 005-007 to validate exposure scope and track remediation

### Compliance Auditing
Use tools 029-030 and 036-037 for continuous compliance monitoring

---

## 🛠️ Requirements

**Python Version:** 3.8+

**No External Dependencies** - All tools use Python standard library only

**Optional Dependencies** (for specific modules only):
- requests - HTTP API calls (tools 019-028, 064)
- paramiko - SSH automation (tools 001, 008)
- python-nmap - Network scanning (tools 015-018)
- volatility - Memory forensics (06_advanced-analysis)

Install per-tool as needed or skip if using standard library tools only.

---

## 📖 Documentation

- **[tools/README.md](./tools/README.md)** - Complete tool catalog with examples
- **[python/README.md](./python/README.md)** - SIEM module architecture and workflows
- Each tool directory includes tool-specific README with features and usage
- Each Python module includes detailed sub-module documentation

---

## 🤝 Best Practices

1. **Always test locally first** - Use `--help` to understand tool options
2. **Check permissions** - Some tools require elevated privileges
3. **Validate output** - Tools use specific formats (JSON, CSV, tables)
4. **Set up logging** - Redirect tool output to files for audit trails
5. **Schedule appropriately** - Use tool 107 for production scheduling
6. **Integrate gradually** - Start with standalone tools, then orchestrate

---

## 🚀 Production Deployment

These tools are production-ready and can be:
- ✅ Deployed as standalone scripts
- ✅ Integrated into existing SIEM platforms
- ✅ Orchestrated through SOAR systems
- ✅ Containerized in Docker for scaling
- ✅ Executed via scheduled tasks or event triggers
- ✅ Integrated into DevSecOps pipelines

---

## 📝 License & Attribution

This portfolio is designed for educational and professional defensive security operations.

---

## 🎯 Quick Tool Reference

| Purpose | Tools |
|---------|-------|
| **Network Discovery** | 001-018 |
| **Threat Intelligence** | 019-030 |
| **Log Analysis** | 031-061 |
| **Malware Analysis** | 062-093 |
| **Behavioral Detection** | 094-105 |
| **Orchestration** | 106-114 |

---

**Ready to deploy?** Start with a single tool from the [tools/README.md](./tools/README.md) or explore the complete [SIEM architecture](./python/README.md).
