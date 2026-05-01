#!/usr/bin/env python3
"""Alert Prioritization Engine - Prioritize alerts by severity"""
import sys

class AlertPrioritizer:
    def __init__(self):
        self.alerts = []
    
    def score_alert(self, alert_type, source_count, failed_attempts):
        """Score alert severity"""
        score = 0
        if alert_type == "brute_force": score += 50
        if alert_type == "malware": score += 100
        score += min(source_count * 5, 30)
        score += min(failed_attempts * 2, 20)
        return min(score, 100)
    
    def prioritize(self, alerts):
        """Prioritize alerts"""
        scored = [(a, self.score_alert(a['type'], a.get('sources', 1), a.get('attempts', 0))) 
                  for a in alerts]
        return sorted(scored, key=lambda x: x[1], reverse=True)

def main():
    prioritizer = AlertPrioritizer()
    alerts = [
        {"type": "brute_force", "sources": 3, "attempts": 50},
        {"type": "port_scan", "sources": 1, "attempts": 0}
    ]
    results = prioritizer.prioritize(alerts)
    for alert, score in results:
        print(f"[!] Priority {score}: {alert['type']}")

if __name__ == "__main__":
    main()
