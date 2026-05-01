# Security Automation: Asset Discovery & Reconnaissance

**Part of the SIEM Architecture** | Layer 1: Data Collection & Normalization

## Overview
This module demonstrates how to automate security reconnaissance, scanning, and asset discovery using Python. These capabilities form the foundation of a security operations program by continuously mapping what's online, discovering services, and monitoring for exposure changes.

## Why This Matters for Your SIEM
In a fully functional SIEM, you need:
- **Real-time asset inventory** - Know what's exposed and what's at risk
- **Continuous monitoring** - Detect configuration changes and new services
- **Enriched data** - Context about systems feeding detection pipelines
- **Automated responses** - Trigger actions when risky exposure is discovered

This module builds these capabilities, feeding your SIEM's asset database and discovery layer.

## Key Topics

### 1. Automated Reconnaissance & Scanning
Automate network reconnaissance using Python to:
- Execute external scanners (nmap, masscan)
- Parse and normalize scan results
- Enrich findings with service detection and version info
- Store results in structured formats for ingestion

**Real-world application**: Continuous asset discovery feeds your SIEM's inventory.

### 2. Manual Port Scanning with Python Sockets
Implement low-level network scanning:
- TCP/UDP port scanning with Python sockets
- Handling timeouts and retries
- Service detection via banner grabbing
- OS fingerprinting

**Real-world application**: When you need custom scanning without external dependencies.

### 3. Scheduling & Continuous Monitoring
Keep your asset inventory fresh:
- Scheduling scans with task schedulers or APScheduler
- Running scans on intervals or based on events
- Logging changes and generating alerts
- Managing scan load and optimizing schedules

**Real-world application**: Your SIEM's data collection layer runs 24/7.

## Tools Included
- **Scanner wrappers**: Execute nmap, masscan, and custom scanners
- **Output parsers**: XML, JSON, CSV parsing
- **Enrichment engines**: Enrich IPs with geolocation, ASN, threat context
- **Change detection**: Identify new services or configuration changes
- **Alerting**: Notify teams of risky discoveries

## Setup & Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Run reconnaissance automation
python automating_recon_and_scanning.py

# Monitor changes continuously
python scheduling_and_continuous_monitoring.py
```

## Connection to SIEM
- **Inputs**: Network devices, cloud APIs, asset management systems
- **Outputs**: Asset inventory, service mappings, exposure reports
- **Feeds**: SIEM asset database, triggers threat hunting queries
- **Example**: "Alert when new SSH service appears on production network"

## Production Considerations
- **Credentials**: Securely store scanner credentials (API keys, SSH keys)
- **Performance**: Schedule scans to avoid network impact
- **Inventory management**: Keep asset database in sync with infrastructure
- **Approval**: Ensure scanning is authorized (avoid offensive scans)

## Files in This Module
```
01_security-automation/
├── Sub_*/ (topic-specific subdirectories)
│   ├── *.py (implementation examples)
│   └── README.md (topic details)
└── README.md (this file)
```
