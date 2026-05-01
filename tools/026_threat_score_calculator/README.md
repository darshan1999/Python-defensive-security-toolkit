# Threat Score Calculator

**Tool Expansion/Abbreviation**: Indicators of Compromise Threat Analysis

**Description**: Tools for enriching indicators of compromise with threat intelligence and prioritizing alerts.

**Key Features**:
- IOC enrichment
- Threat scoring
- Geolocation lookup
- Alert prioritization

**Use Cases**:
- Defensive security monitoring and threat detection
- Incident response and forensic analysis  
- Security compliance and audit verification
- Asset management and inventory tracking
- Vulnerability assessment and remediation
- Threat intelligence correlation and enrichment

**Real-world Application for Security Engineers**: SOC analysts use these tools to automatically enrich detected IOCs with geolocation, reputation, and historical threat data. This speeds incident response and helps distinguish between legitimate traffic and genuine threats, reducing alert fatigue.

**How to Run the Tool**:
1. Install dependencies: `pip install -r requirements.txt`
2. Run the tool: `python3 threat_score_calculator.py [arguments]`
3. Configure inputs and parameters as needed
4. Review output and integrate with SIEM/ticketing systems
5. Set up alerts and automated responses as appropriate

**Example Output**:
```
[*] Starting scan...
[+] Processing target...
[*] Analysis complete
[+] Results: Data successfully processed
[!] Important findings identified - review immediately
```