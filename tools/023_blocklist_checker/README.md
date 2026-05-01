# 023 - Blocklist Checker

**Purpose**: Threat Intelligence - IP/Domain Validation

**Description**: Validates IPs and domains against local blocklists and public threat intelligence APIs (AbuseIPDB). Provides confidence scoring and batch processing capabilities for rapid IOC validation.

**Key Features**:
- ✅ Validates both IPv4/IPv6 addresses and domain names
- ✅ Local file-based blocklist support (one entry per line)
- ✅ AbuseIPDB API integration with confidence scoring
- ✅ Severity classification: BLOCKED, MALICIOUS (>50%), SUSPICIOUS (1-50%), CLEAN
- ✅ Batch mode for processing multiple targets from file
- ✅ JSON output for SIEM integration
- ✅ Sample blocklist generation for testing
- ✅ Fallback to local blocklist if API unavailable

**Real-world Application for Security Engineers**: 
SOC analysts use this tool during incident response to rapidly validate IPs and domains flagged in alerts. The dual-layer approach (local blocklist + cloud API) provides immediate results even without internet access, while the confidence scoring helps prioritize which alerts require deeper investigation.

**Installation**:
```bash
# No external dependencies - uses Python standard library only
python3 blocklist_checker.py --help
```

**Usage Examples**:

**1. Create Sample Blocklist**:
```bash
python3 blocklist_checker.py --create-sample
# Creates: blocklist.txt with 10 example malicious IPs
```

**2. Check Single IP Against Local Blocklist**:
```bash
python3 blocklist_checker.py 8.8.8.8 --blocklist blocklist.txt
```

**3. Check Single IP Against AbuseIPDB API**:
```bash
python3 blocklist_checker.py 1.2.3.4 --api-key YOUR_ABUSEIPDB_KEY
# Or use environment variable: export ABUSEIPDB_API_KEY=YOUR_KEY
python3 blocklist_checker.py 1.2.3.4
```

**4. Check Multiple Targets**:
```bash
python3 blocklist_checker.py 1.2.3.4 2.3.4.5 evil.com --blocklist blocklist.txt
```

**5. Batch Processing From File**:
```bash
python3 blocklist_checker.py --file targets.txt --blocklist blocklist.txt --output results.json
# targets.txt contains one IP/domain per line
```

**Output Format**:

**Console (Table)**:
```
Target                         Status       Info                          
========================================================================
1.2.3.4                        MALICIOUS    AbuseIPDB: 75% confidence      
evil.com                       BLOCKED      Found in local blocklist       
8.8.8.8                        CLEAN        Not found in any list          
```

**JSON Output** (--output results.json):
```json
{
  "results": [
    {
      "target": "1.2.3.4",
      "status": "MALICIOUS",
      "confidence": 75,
      "source": "AbuseIPDB",
      "report_count": 12
    }
  ],
  "summary": {
    "checked": 3,
    "blocked": 1,
    "malicious": 1,
    "suspicious": 0,
    "clean": 1
  }
}
```

**Severity Mapping**:
- **BLOCKED**: Found in local blocklist (immediate threat)
- **MALICIOUS**: AbuseIPDB confidence > 50% (high threat)
- **SUSPICIOUS**: AbuseIPDB confidence 1-50% (monitor)
- **CLEAN**: Not found anywhere (low threat)

**Integration Tips**:
- Use with tool 046 (Multi-Format Exporter) for batch reporting
- Combine with tool 019 (IP Geolocation) for location correlation
- Feed results into tool 104 (Behavior Report Generator) for incident reporting
- Schedule with tool 107 (Task Runner) for continuous validation

**API Rate Limits**:
- AbuseIPDB: ~5-second delay between requests recommended
- Local blocklist: No limits (instant)
- Batch mode: Automatically paces API calls

**Exit Codes**:
- `0` - Success (targets checked)
- `1` - Error (missing file, invalid API key, etc.)