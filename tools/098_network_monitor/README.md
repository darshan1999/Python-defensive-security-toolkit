# 098 - Network Monitor

**Purpose**: Behavioral Detection - Network Connection Monitoring

**Description**: Monitors network connections for C2 (Command & Control) beaconing, lateral movement, and data exfiltration. Identifies suspicious patterns in connection behavior and flags abnormal networking activity.

**Key Features**:
- ✅ Parses both `ss -tan` and `netstat -tan` output formats
- ✅ Detects C2 beaconing (same IP with multiple connections, similar timing intervals)
- ✅ Monitors known C2 ports (4444, 1337, 31337, 12345, 54321, 8888, 9999)
- ✅ Identifies connection floods (>10 concurrent connections to same IP)
- ✅ Detects unusual high ports (>10000) that are ESTABLISHED
- ✅ Flags lateral movement on SMB (445), RDP (3389), WMI (135), SSH (22) between internal IPs
- ✅ Counts connections per destination IP for threat scoring
- ✅ JSON output for SIEM integration
- ✅ Cross-platform support (Linux, macOS, Windows)

**Real-world Application for Security Engineers**: 
SOC analysts use this tool to detect advanced threats that exfiltrate data slowly (beaconing) or move laterally through the network. The connection flood detection catches DDoS-like attacks, while the C2 port monitoring identifies callback activity to known malicious infrastructure.

**Installation**:
```bash
# No external dependencies - uses subprocess and standard library
python3 network_monitor.py --help
```

**Usage Examples**:

**1. Scan Live Network Connections**:
```bash
python3 network_monitor.py
```

**2. Parse Network Dump From File**:
```bash
ss -tan > network_dump.txt
python3 network_monitor.py --input network_dump.txt
```

**3. Export Results as JSON**:
```bash
python3 network_monitor.py --output suspicious_connections.json
```

**Output Format**:

**Console**:
```
[+] Network Monitor Report
    Total connections: 147
    C2 indicators: 3
    Lateral movement: 2
    Exfiltration alerts: 5

[!] C2 BEACONING INDICATORS:

    IP: 192.168.100.50
    Connections: 5 to port 4444
    Status: SUSPICIOUS (C2 port, multiple connections)
    
    IP: 10.0.0.25
    Connections: 8 to port 1337
    Status: SUSPICIOUS (C2 port, connection flood)

[!] LATERAL MOVEMENT DETECTED:

    From: 192.168.1.100 → To: 192.168.1.50 on port 445 (SMB)
    Status: SUSPICIOUS (internal network, SMB traffic)

[!] EXFILTRATION ALERTS:

    Destination: 203.0.113.50
    Connection Count: 11
    Status: HIGH (flood pattern detected)
```

**JSON Output** (--output suspicious_connections.json):
```json
{
  "report": {
    "total_connections": 147,
    "alerts": {
      "c2_indicators": 3,
      "lateral_movement": 2,
      "exfiltration": 5
    },
    "c2_beaconing": [
      {
        "destination_ip": "192.168.100.50",
        "port": 4444,
        "connection_count": 5,
        "severity": "HIGH",
        "reason": "C2 port with multiple connections"
      }
    ],
    "lateral_movement": [
      {
        "source_ip": "192.168.1.100",
        "dest_ip": "192.168.1.50",
        "port": 445,
        "service": "SMB",
        "severity": "HIGH"
      }
    ]
  }
}
```

**Detection Types**:

| Indicator | Threshold | Severity |
|-----------|-----------|----------|
| **C2 Port** | Any traffic on 4444, 1337, 31337, etc | HIGH |
| **Beaconing** | Same IP with 3+ connections | HIGH |
| **Connection Flood** | >10 to same IP | CRITICAL |
| **High Port (Established)** | Port >10000 in ESTABLISHED state | MEDIUM |
| **Lateral Movement** | SMB/RDP/SSH/WMI between internal IPs | HIGH |

**C2 Ports Monitored**:
- 4444 (Metasploit default)
- 1337 (Common leet port)
- 31337 (Back Orifice default)
- 12345 (Netbus default)
- 54321 (Custom C2)
- 8888 (HTTP alt)
- 9999 (Custom C2)

**Integration Tips**:
- Combine with tool 096 (Process Monitor) for complete behavioral analysis
- Use with tool 095 (Filesystem Monitor) to correlate file activity
- Feed results into tool 104 (Behavior Report Generator) for incident reporting
- Integrate into SIEM via JSON for continuous network monitoring
- Use with tool 099 (Persistence Detector) to find persistence post-compromise

**Cross-Platform Behavior**:
- **Linux**: Uses `ss -tan` preferred, falls back to `netstat -tan`
- **macOS**: Uses `netstat -tan`
- **Windows**: Uses `netstat -ano`
- Handles all platforms with automatic format detection

**Performance Considerations**:
- Network scan completes in <5 seconds on typical systems
- Minimal CPU overhead (<1%)
- Designed for continuous scheduling

**High Connection Threshold**:
- Connections >5 to same IP flagged as suspicious
- Connections >10 flagged as potential DDoS/exfiltration

**Exit Codes**:
- `0` - Success (network analyzed)
- `1` - Error (permission denied, parsing error, etc.)