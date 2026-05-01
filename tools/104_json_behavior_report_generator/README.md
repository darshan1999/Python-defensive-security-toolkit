# 104 - JSON Behavior Report Generator

**Purpose**: Incident Reporting - Structured Threat Analysis Reports

**Description**: Generates structured incident reports from behavioral event data with MITRE ATT&CK technique mapping, severity aggregation, timeline reconstruction, and key findings extraction.

**Key Features**:
- ✅ Generates UUID-based report IDs for incident tracking
- ✅ MITRE ATT&CK mapping (T1059, T1071, T1565, T1112, T1547, T1021)
- ✅ Severity breakdown (CRITICAL, HIGH, MEDIUM, LOW)
- ✅ Executive summary with event statistics
- ✅ Timeline reconstruction grouped by hour
- ✅ Top indicators and most frequent event types
- ✅ Findings extraction (critical and high severity events only)
- ✅ Multiple output formats (summary, full report)
- ✅ JSON input/output for SIEM integration
- ✅ Analyst hostname in report metadata

**Real-world Application for Security Engineers**: 
Analysts use this tool to convert raw security events into executive-ready incident reports. The MITRE ATT&CK mapping helps leadership understand adversary tactics, while the severity breakdown prioritizes remediation efforts.

**Installation**:
```bash
# No external dependencies - uses json and uuid from standard library
python3 json_behavior_report_generator.py --help
```

**Usage Examples**:

**1. Generate Summary Report**:
```bash
python3 json_behavior_report_generator.py --input events.json --format summary
```

**2. Generate Full Report**:
```bash
python3 json_behavior_report_generator.py --input events.json --format full
```

**3. Export to File**:
```bash
python3 json_behavior_report_generator.py --input events.json --output incident_123.json
```

**Input Format** (events.json):
```json
[
  {
    "timestamp": "2026-04-30T10:00:00",
    "event_type": "process_creation",
    "source": "host1",
    "details": "cmd.exe spawned with suspicious arguments",
    "severity": "HIGH"
  },
  {
    "timestamp": "2026-04-30T10:05:00",
    "event_type": "network_connection",
    "source": "host1",
    "details": "Connection to 192.168.1.100:4444",
    "severity": "CRITICAL"
  },
  {
    "timestamp": "2026-04-30T10:10:00",
    "event_type": "file_modification",
    "source": "host1",
    "details": "/tmp/payload.exe created",
    "severity": "HIGH"
  }
]
```

**Output Format** (Summary):

**Console**:
```
[+] Behavior Report Generated
    Total events: 3
    CRITICAL: 1
    HIGH: 2
    MEDIUM: 0
    LOW: 0
    Unique sources: 1
    MITRE techniques: 3
    Time range: 2026-04-30 10:00:00 → 2026-04-30 10:10:00
```

**Full JSON Report Output**:
```json
{
  "metadata": {
    "report_id": "ebd27304-814d-40a5-b6a3-17fb8f3f9e06",
    "generated_at": "2026-04-30T10:15:00.123456",
    "analyst": "hostname",
    "tool_version": "1.0"
  },
  "executive_summary": {
    "total_events": 3,
    "critical_count": 1,
    "high_count": 2,
    "medium_count": 0,
    "low_count": 0,
    "unique_sources": 1,
    "time_range": {
      "start": "2026-04-30T10:00:00",
      "end": "2026-04-30T10:10:00",
      "duration_minutes": 10
    }
  },
  "mitre_mapping": {
    "T1059": {
      "technique": "Command and Scripting Interpreter",
      "count": 1,
      "events": ["process_creation"]
    },
    "T1071": {
      "technique": "Application Layer Protocol",
      "count": 1,
      "events": ["network_connection"]
    },
    "T1565": {
      "technique": "Data Manipulation",
      "count": 1,
      "events": ["file_modification"]
    }
  },
  "timeline": {
    "2026-04-30 10:00": {
      "event_count": 2,
      "events": [...]
    }
  },
  "top_indicators": [
    {
      "event_type": "process_creation",
      "count": 1,
      "severity": "HIGH"
    }
  ],
  "findings": [
    {
      "timestamp": "2026-04-30T10:00:00",
      "event_type": "process_creation",
      "severity": "HIGH",
      "source": "host1",
      "details": "cmd.exe spawned with suspicious arguments"
    }
  ]
}
```

**MITRE ATT&CK Mapping**:

| Event Type | Technique ID | Technique Name |
|-----------|--------------|----------------|
| **process_creation** | T1059 | Command and Scripting Interpreter |
| **network_connection** | T1071 | Application Layer Protocol |
| **file_modification** | T1565 | Data Manipulation |
| **registry_modification** | T1112 | Modify Registry |
| **persistence** | T1547 | Boot or Logon Autostart Execution |
| **lateral_movement** | T1021 | Remote Services |

**Severity Levels**:
- **CRITICAL**: Requires immediate response (confirmed malware, active breach)
- **HIGH**: Urgent investigation (suspicious behavior, potential compromise)
- **MEDIUM**: Should investigate (anomalous activity, possible threat)
- **LOW**: Monitor (informational, false positives likely)

**Integration Tips**:
- Input from tool 096 (Process Monitor) events
- Input from tool 098 (Network Monitor) events
- Input from tool 095 (Filesystem Monitor) events
- Output to tool 046 (Multi-Format Exporter) for distribution
- Feed into SIEM platforms for ticketing and tracking
- Use with tool 112 (Multi-Format Report Generator) for custom formatting

**Timeline Grouping**:
- Events grouped by hour
- Each hour shows event count and full event details
- Enables trend analysis (spike detection, patterns over time)

**Findings Extraction**:
- Only CRITICAL and HIGH severity events included
- Sorted by timestamp
- Full event details provided for analyst review

**Format Options**:
- `--format summary` - Executive summary only (fast, 500 bytes)
- `--format full` - Complete report with timeline and findings (5KB+)

**Exit Codes**:
- `0` - Success (report generated)
- `1` - Error (invalid JSON input, missing required fields, etc.)