# Detection Engineering: SIEM, EDR & Firewall Integration

**Part of the SIEM Architecture** | Layer 5: Integration with Security Tools

## Overview
This module brings everything together—the orchestration layer of your SIEM. Learn to integrate with SIEM platforms (Splunk, ELK), EDR systems (CrowdStrike, Sentinel One), firewalls, and threat feeds. Build custom detection pipelines, implement real-time alerting, automate response actions, and conduct threat hunting at scale.

## Why This Matters for Your SIEM
A fully functional SIEM is only effective if its output feeds action:
- **SIEM integration** - Normalize and send events to central platform
- **EDR integration** - Correlated endpoint and network detection
- **Firewall automation** - Auto-block malicious IPs in real-time
- **Detection pipelines** - Custom logic for your specific threats
- **Alerting** - Smart routing to the right team
- **Response automation** - Containment without manual intervention

This module transforms your SIEM from a reporting tool into an operational security platform.

## Key Topics

### 1. Integrating with SIEM Platforms
Send data to your SIEM:
- Splunk HTTP Event Collector (HEC)
- Elasticsearch bulk API
- Syslog/CEF protocols
- Custom REST APIs
- Data normalization for ingestion

**Real-world application**: Your custom detection scripts feed Splunk/ELK dashboards.

### 2. Sending Events to SIEM
Multiple transport options:
- Syslog (UDP/TCP) for traditional systems
- HTTP/HTTPS for modern platforms
- JSON payloads for context-rich events
- Batching for performance
- Retry logic for reliability

**Real-world application**: 24/7 event streaming to central platform.

### 3. Interacting with EDRs via APIs
Consume endpoint data:
- CrowdStrike API (query detections, incidents)
- Sentinel One API (endpoint events, threat intelligence)
- Carbon Black API (process events, file hashing)
- Query for specific behaviors or artifacts
- Correlate endpoint activity with network events

**Real-world application**: When network IDS detects C2 activity, check if endpoint processes it.

### 4. Building Custom Detection Pipelines
Create your detection logic:
- Define threat models (what you're hunting for)
- Write rules in Python (not just vendor syntax)
- Multi-stage correlations (event A + B = alert)
- Temporal analysis (happened within 5 minutes?)
- Statistical baselines (abnormal for this user?)

**Real-world application**: Vendor rules catch 80% of threats; custom rules catch your threats.

### 5. Real-Time Alerting & Response Automation
Close the loop:
- Alert routing (right team for right threat)
- Escalation policies (page on-call engineer if critical)
- Response actions (disable account, isolate host, revoke token)
- SOAR integration (orchestrate complex response workflows)
- Feedback loops (learn from false positives)

**Real-world application**: Detect, alert, and contain a breach in minutes, not hours.

### 6. Custom Dashboards & Visualizations
Operational visibility:
- Real-time threat status (active incidents, top IPs, users)
- KPIs for management (detection rate, MTTR, cost saved)
- Threat hunting dashboards (search, filter, correlate)
- Executive summaries (brief reports for board)

**Real-world application**: Leadership sees ROI of security program.

### 7. Threat Hunting Automation
Proactive threat search:
- Hunting queries (find suspicious patterns)
- Hypothesis-based hunting (test theory against data)
- Campaign tracking (link events to known actors)
- Timeline reconstruction (build incident timeline)

**Real-world application**: Don't wait for alerts—hunt proactively.

## Tools Included
- **SIEM connectors**: Splunk, ELK, Sumologic, LogRhythm
- **EDR integrators**: CrowdStrike, Sentinel One, Carbon Black, Falcon
- **Firewall APIs**: Palo Alto, Fortinet, Cisco, pfSense
- **Alert routers**: Slack, PagerDuty, email, ticketing systems
- **Detection frameworks**: Custom rule engines, correlation logic
- **Hunting platforms**: Query builders, timeline tools
- **SOAR connectors**: Orchestration for automated response

## Setup & Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Send data to SIEM
python integrating_with_siem_platforms_using_python.py

# Send events to Splunk HEC
python sending_events_to_siem_syslog_http_json_udp.py

# Query EDR for detections
python interacting_with_edrs_via_apis_crowdstrike_sentinelone_xdrs.py

# Build custom detection pipeline
python building_custom_detection_pipelines.py

# Real-time alerting
python real_time_alerting_and_response_automation.py

# Threat hunting
python threat_hunting_automation_with_siem_python.py

# Dashboards
python custom_dashboards_from_siemedr_data.py
```

## Connection to SIEM
- **Inputs**: All previous modules (reconnaissance, logs, TI, malware analysis)
- **Outputs**: Alerts, dashboards, automated responses, hunt results
- **Integration**: SIEM platform, EDR/XDR, firewalls, SOAR
- **Example**: 
  1. Asset automation discovers new SSH on prod
  2. SOC analysis shows suspicious login attempts
  3. TI enrichment reveals source IP is known C2
  4. EDR integration confirms process execution on endpoint
  5. Auto-response: disable account, isolate host, block IP on firewall
  6. Dashboard: executive briefing 15 minutes later

## Production Considerations
- **API credentials**: Securely store and rotate API keys
- **Rate limiting**: Respect API quotas, implement backoff
- **Error handling**: Graceful degradation if APIs are down
- **Compliance**: Ensure automated actions are auditable
- **Testing**: Validate response actions in staging before production
- **Feedback**: Tune detections based on false positive rates

## Files in This Module
```
05_detection-engineering/
├── Sub_*/ (topic-specific subdirectories)
│   ├── *.py (implementation examples)
│   └── README.md (topic details)
└── README.md (this file)
```
