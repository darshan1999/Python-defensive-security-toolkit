# Threat Intelligence: Enrichment & IOC Integration

**Part of the SIEM Architecture** | Layer 3: Intelligence & Enrichment

## Overview
This module teaches how to consume, normalize, and integrate external threat intelligence feeds with your detection systems. Learn to enrich Indicators of Compromise (IOCs) with threat context, generate actionable reports, and automate intelligence integration into SIEM detection pipelines.

## Why This Matters for Your SIEM
Raw events are noise. Threat intelligence adds signal:
- **Contextualization** - Know if detected IP is known C2, proxy, or hosting provider
- **Prioritization** - Focus on high-confidence threats vs. background noise
- **Automation** - Auto-block known malicious IPs, domains, file hashes
- **Trending** - Identify campaigns, threat actors, geographic patterns
- **Compliance** - Demonstrate due diligence in threat landscape monitoring

This module transforms your SIEM from reactive (detecting anomalies) to proactive (hunting known threats).

## Key Topics

### 1. Consuming Threat Intelligence Feeds
Integrate multiple intelligence sources:
- Public feeds (AlienVault OTX, Cyber Threat Coalition)
- Commercial feeds (Mandiant, CrowdStrike, Proofpoint)
- Community intelligence (MISP instances, GitHub indicators)
- Internal threat tracking (past incidents, custom blocklists)
- Standards: STIX, TAXII, OpenIOC, CSV, JSON

**Real-world application**: Your SIEM updates threat feeds hourly or in real-time.

### 2. Enriching IOCs via APIs
Look up IOC context:
- IP reputation (AbuseIPDB, Shodan)
- Domain registration & DNS history (WHOIS, VirusTotal)
- File hash analysis (VirusTotal, Hybrid Analysis)
- Email infrastructure (MX records, SPF/DKIM config)
- Malware family classification (Kaspersky, Sophos)

**Real-world application**: When alert triggers on unknown IP, immediately know its history.

### 3. Normalizing & Deduplicating Intelligence
Handle messy feeds:
- Parse diverse IOC formats (STIX, Snort rules, plain text)
- Deduplicate from multiple sources
- Normalize indicators (standardize domains, URLs)
- Handle false positives (remove indicators known to be legit)
- Assign confidence scores

**Real-world application**: Prevent alert fatigue from duplicate indicators.

### 4. Generating Actionable Reports & Indicators
Create intelligence products:
- IOC summaries (top IPs, domains, hashes this week)
- Campaign reports (attribution, TTPs, timeline)
- Risk scores (incorporate source reliability, age, severity)
- Recommendations (block, monitor, investigate)

**Real-world application**: Management & SOC teams make decisions based on reports.

### 5. Integrating Intelligence with Detection Pipelines
Close the loop:
- Ingest fresh indicators into SIEM
- Trigger alerts when events match known-bad indicators
- Update firewall/EDR blocklists programmatically
- Correlate detected IPs with threat actor profiles
- Hunt for past occurrences of newly identified indicators

**Real-world application**: Detect "Patient Zero" in your infrastructure within minutes of TI update.

## Tools Included
- **Feed consumers**: HTTP, TAXII, MISP API clients
- **Parsers**: STIX, CSV, JSON, custom format handlers
- **Enrichers**: VirusTotal, Shodan, whois, DNS lookup integrations
- **Deduplicators**: Normalize and merge indicators from multiple sources
- **Reporters**: Generate actionable intelligence summaries
- **Integrators**: Push indicators to SIEM, firewall, EDR platforms

## Setup & Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Consume threat feeds
python consuming_threat_intelligence_feeds.py

# Enrich IOCs
python enriching_iocs_via_apis.py

# Correlate with internal data
python correlating_external_intelligence_with_internal_logs.py

# Generate reports
python generating_actionable_reports_and_iocs.py
```

## Connection to SIEM
- **Inputs**: External feeds, internal threat tracking, incident data
- **Outputs**: Enriched IOC database, alerts, reports, recommendations
- **Feeds**: Detection engines (block/watch lists), hunt queries, risk scores
- **Example**: "New APT campaign detected targeting finance sector—audit our logs for indicators"

## Production Considerations
- **Feed reliability**: Sources have varying accuracy; implement confidence scoring
- **Feed freshness**: Stale indicators are useless; update frequently
- **Privacy**: Be careful sharing IOCs externally (avoid leaking internal infrastructure)
- **Legal**: Verify TLP (Traffic Light Protocol) markings before sharing
- **Performance**: Optimize lookups (cache results, batch requests)
- **Cost**: Commercial APIs can be expensive; prioritize high-value queries

## Files in This Module
```
03_threat-intelligence/
├── Sub_*/ (topic-specific subdirectories)
│   ├── *.py (implementation examples)
│   └── README.md (topic details)
└── README.md (this file)
```
