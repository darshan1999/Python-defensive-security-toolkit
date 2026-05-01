#!/usr/bin/env python3
"""
Threat Score Calculator - Calculate composite threat score for IPs or domains.
"""

import sys, argparse, json
from datetime import datetime

class ThreatScoreCalculator:
    """Calculate composite threat score with weighted risk factors."""
    
    WEIGHTS = {"failed_logins": 2, "port_scan": 20, "malware_domain": 50, "unusual_country": 15, "after_hours": 10, "repeated_alerts": 5}
    
    def __init__(self):
        self.score = 0
        self.components = {}
    
    def calculate_score(self, failed_login_count=0, port_scan_detected=False, known_malware_domain=False,
                       unusual_country=False, after_hours_activity=False, repeated_alerts=False):
        """Calculate threat score from indicators."""
        score = 0
        score += min(failed_login_count, 25) * self.WEIGHTS["failed_logins"]
        self.components["failed_logins"] = min(failed_login_count, 25) * self.WEIGHTS["failed_logins"]
        score += (20 if port_scan_detected else 0); self.components["port_scan"] = 20 if port_scan_detected else 0
        score += (50 if known_malware_domain else 0); self.components["malware_domain"] = 50 if known_malware_domain else 0
        score += (15 if unusual_country else 0); self.components["unusual_country"] = 15 if unusual_country else 0
        score += (10 if after_hours_activity else 0); self.components["after_hours"] = 10 if after_hours_activity else 0
        score += (5 if repeated_alerts else 0); self.components["repeated_alerts"] = 5 if repeated_alerts else 0
        self.score = min(score, 100)
        return self.score
    
    def get_severity(self, score=None):
        """Determine severity classification from score."""
        score = score or self.score
        if score >= 80: return "CRITICAL"
        elif score >= 60: return "HIGH"
        elif score >= 40: return "MEDIUM"
        elif score >= 20: return "LOW"
        else: return "MINIMAL"
    
    def get_recommendations(self, score=None):
        """Get recommended actions based on threat score."""
        score = score or self.score
        if score >= 80: return ["Block immediately", "Investigate account", "Enable MFA"]
        elif score >= 60: return ["Review activity", "Consider blocking", "Enable monitoring"]
        elif score >= 40: return ["Monitor closely", "Review access patterns"]
        elif score >= 20: return ["Log activity"]
        else: return ["No action required"]
    
    def report(self, target, score=None):
        """Display threat score report."""
        score = score or self.score
        severity = self.get_severity(score)
        recommendations = self.get_recommendations(score)
        print("\n" + "="*60)
        print("THREAT SCORE REPORT")
        print("="*60)
        print(f"Target: {target} | Score: {score}/100 | Severity: {severity}")
        print("\nScore Components:")
        for component, value in self.components.items():
            if value > 0: print(f"  {component:20s}: {value:3d}")
        print("\nRecommended Actions:")
        for i, rec in enumerate(recommendations, 1): print(f"  {i}. {rec}")
        print("="*60)

def main():
    if "--example" in sys.argv:
        print("Usage:\n  python3 threat_score_calculator.py 192.168.1.100 -f 10 -p -u\n  python3 threat_score_calculator.py malicious.com -m -r --json"); sys.exit(0)
    parser = argparse.ArgumentParser(description="Calculate composite threat score")
    parser.add_argument("target", help="IP address or domain to score")
    parser.add_argument("-f", "--failed-logins", type=int, default=0, help="Failed login attempts")
    parser.add_argument("-p", "--port-scan", action="store_true", help="Port scan detected")
    parser.add_argument("-m", "--malware-domain", action="store_true", help="On malware domain list")
    parser.add_argument("-u", "--unusual-country", action="store_true", help="Unexpected country")
    parser.add_argument("-a", "--after-hours", action="store_true", help="After hours activity")
    parser.add_argument("-r", "--repeated-alerts", action="store_true", help="Multiple alerts")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()
    calculator = ThreatScoreCalculator()
    score = calculator.calculate_score(args.failed_logins, args.port_scan, args.malware_domain, args.unusual_country, args.after_hours, args.repeated_alerts)
    if args.json:
        output = {"target": args.target, "score": score, "severity": calculator.get_severity(score), "components": calculator.components, "recommendations": calculator.get_recommendations(score)}
        print(json.dumps(output, indent=2))
    else:
        calculator.report(args.target, score)

if __name__ == "__main__":
    main()
