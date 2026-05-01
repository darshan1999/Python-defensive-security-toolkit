# SOC Analysis: Log Ingestion, Normalization & Detection

**Part of the SIEM Architecture** | Layer 2: Log Ingestion & Analysis

## Overview
This module demonstrates how to build the detection engine of your SIEM. Learn to ingest logs from diverse sources (firewalls, endpoints, auth systems, web servers, cloud platforms), normalize them to standard formats, and detect anomalies and security behaviors in real-time.

## Why This Matters for Your SIEM
A SIEM without detection is just a data lake. This module teaches:
- **Log aggregation** - Pulling from dozens of sources simultaneously
- **Normalization** - Converting diverse formats (Syslog, JSON, CEF, W3C) to a common schema
- **Detection logic** - Rules, correlations, and behavioral analysis
- **Alerting** - Generating actionable alerts from noise
- **Investigation** - Structured data enabling faster incident response

This module is the heartbeat of your SIEM—where raw events become intelligence.

## Key Topics

### 1. Parsing Logs from Multiple Sources
Ingest and parse logs from:
- Firewalls (iptables, pfsense, FortiGate)
- Linux/Windows authentication logs
- Web server access logs (Apache, Nginx, IIS)
- EDR platforms (via APIs)
- Cloud services (AWS, Azure, GCP)
- Application logs (custom formats)

**Real-world application**: Your SIEM ingests 1000s of events/second from all these sources.

### 2. Normalization to Common Schema
Convert varied log formats to standard structure:
- Elastic Common Schema (ECS)
- Syslog/CEF standards
- Custom normalized JSON

**Fields standardized**: timestamp, source_ip, user, action, status, risk_level, etc.

**Real-world application**: Detection rules work on normalized data, not raw logs.

### 3. Behavior Detection & Anomaly Detection
Detect suspicious patterns:
- Failed login attempts & brute force
- Unusual outbound connections
- Large data transfers
- Privilege escalation attempts
- Off-hours access
- Lateral movement indicators

**Real-world application**: Catch attacks that don't match known signatures.

### 4. Event Correlation Across Multiple Sources
Link events from different systems:
- **Scenario**: Firewall detects connection → EDR detects process spawn → DLP detects file upload
- **Individually**: Each might be benign
- **Correlated**: Clear data exfiltration attack

**Real-world application**: Reduce false positives, identify complex attacks.

### 5. Exporting to Dashboards & Reports
Present findings:
- CSV export for spreadsheet analysis
- JSON/Parquet for data science teams
- Excel pivot tables for executives
- Real-time dashboards (integration with Grafana, Kibana)

**Real-world application**: Stakeholders need visibility into security events.

## Tools Included
- **Log parsers**: Regex, JSON, CEF, Syslog, custom formats
- **Normalizers**: Map diverse fields to standard schema
- **Detectors**: Rule engine, anomaly models, statistical analysis
- **Correlators**: Multi-source event linking, timeline reconstruction
- **Exporters**: CSV, Excel, JSON, dashboard integration

## Setup & Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Parse and normalize logs
python parsing_and_normalizing_logs.py

# Detect suspicious patterns
python behavioral_detection.py

# Correlate multi-source events
python event_correlation_across_multiple_sources.py

# Export findings
python exporting_data_to_dashboards_csv_excel_json.py
```

## Connection to SIEM
- **Inputs**: Raw logs from all infrastructure (170+ log types)
- **Outputs**: Normalized events, alerts, dashboards
- **Feeds**: Detection engines, incident queues, executive dashboards
- **Example**: "Alert security team of 10+ failed logins in 5 minutes from single IP"

## Production Considerations
- **Performance**: Process 1000s of events/second
- **Storage**: Design retention policies (hot/warm/cold data)
- **Compliance**: Ensure log ingestion meets regulatory requirements (SOX, HIPAA, PCI)
- **Privacy**: Mask sensitive data (PII, credentials) in logs
- **Accuracy**: Regular tuning to reduce false positives

## Files in This Module
```
02_soc-analysis/
├── Sub_*/ (topic-specific subdirectories)
│   ├── *.py (implementation examples)
│   └── README.md (topic details)
└── README.md (this file)
```
