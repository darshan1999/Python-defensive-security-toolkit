# 096 - Process Monitor

**Purpose**: Behavioral Detection - Runtime Process Monitoring

**Description**: Monitors running processes for suspicious activity, behavioral indicators, and injection attempts. Detects malicious process names, suspicious execution locations, encoded commands, and unusual parent-child relationships.

**Key Features**:
- ✅ Correctly parses `ps aux` output (all 11 fields: USER, PID, %CPU, %MEM, VSZ, RSS, TTY, STAT, START, TIME, COMMAND)
- ✅ Detects suspicious execution locations (/tmp/, /dev/shm/, /var/tmp/)
- ✅ Flags suspicious process names (nc, ncat, netcat, meterpreter, mimikatz, cobaltstrike)
- ✅ Detects encoded PowerShell commands (-enc, -encodedcommand, -e with base64)
- ✅ Identifies unusual parent-child relationships (e.g., web server spawning bash)
- ✅ Alerts on high CPU processes (>90% for extended periods)
- ✅ Cross-platform support (Linux, macOS, Windows with graceful fallback)
- ✅ JSON output for SIEM integration

**Real-world Application for Security Engineers**: 
EDR analysts use this tool to identify malware persistence and command execution on endpoints. The detection of encoded PowerShell commands catches obfuscated attacks, while suspicious location detection catches fileless malware hiding in /tmp or /dev/shm.

**Installation**:
```bash
# No external dependencies - uses subprocess and standard library
python3 process_monitor.py --help
```

**Usage Examples**:

**1. Scan All Processes (Live System)**:
```bash
python3 process_monitor.py
```

**2. Parse Process List From File**:
```bash
ps aux > process_dump.txt
python3 process_monitor.py --input process_dump.txt
```

**3. Export Results as JSON**:
```bash
python3 process_monitor.py --output suspicious_processes.json
```

**Output Format**:

**Console**:
```
[+] Process Monitor Report
    Total processes: 245
    Suspicious: 4

[!] SUSPICIOUS PROCESSES:

    PID 1234: Suspicious location: /tmp/malware
    Command: /tmp/malware/payload.elf
    
    PID 5678: Suspicious name: nc
    Command: nc -l -p 4444
    
    PID 9012: Encoded command
    Command: powershell.exe -enc QmF...
    
    PID 3456: Unusual parent: apache → /bin/bash
    Parent: apache (PID 1234)
    Command: /bin/bash -i
```

**JSON Output** (--output suspicious_processes.json):
```json
{
  "report": {
    "total_processes": 245,
    "suspicious_count": 4,
    "suspicious_processes": [
      {
        "pid": 1234,
        "user": "root",
        "command": "/tmp/malware/payload.elf",
        "indicators": ["suspicious_location"],
        "severity": "CRITICAL"
      }
    ]
  }
}
```

**Detection Types**:

| Indicator | Example | Severity |
|-----------|---------|----------|
| **Suspicious Location** | /tmp/malware, /dev/shm/x, /var/tmp/y | CRITICAL |
| **Suspicious Process Name** | nc, mimikatz, cobaltstrike | CRITICAL |
| **Encoded Commands** | powershell -enc QmF... | HIGH |
| **Unusual Parent-Child** | apache → bash | HIGH |
| **Empty/Short Name** | <, >, (empty) | MEDIUM |
| **High CPU** | 150% for extended period | MEDIUM |

**Integration Tips**:
- Combine with tool 097 (Registry Monitor) for complete behavioral analysis
- Use with tool 099 (Persistence Detector) to find rootkits
- Feed suspicious PIDs into tool 105 (ASEP Detector) for persistence check
- Integrate into SIEM via JSON output for continuous monitoring

**Cross-Platform Behavior**:
- **Linux/macOS**: Uses `ps aux` via subprocess (always works)
- **Windows**: Uses `tasklist /fo csv` with graceful fallback
- Handles both platforms with try/except ImportError for platform-specific modules

**Performance Considerations**:
- Scans complete system in <2 seconds on typical systems
- Minimal CPU overhead (<1%)
- No dependencies on external services

**Exit Codes**:
- `0` - Success (processes scanned)
- `1` - Error (permission denied, invalid input, etc.)