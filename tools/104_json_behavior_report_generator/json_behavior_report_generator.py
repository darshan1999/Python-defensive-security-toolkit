#!/usr/bin/env python3
"""JSON Behavior Report Generator - Creates structured reports with MITRE mapping."""

import sys, json, argparse, socket, uuid
from datetime import datetime
from collections import Counter, defaultdict

MITRE_MAPPING = {
    'process_creation': 'T1059',
    'network_connection': 'T1071',
    'file_modification': 'T1565',
    'registry_modification': 'T1112',
    'persistence': 'T1547',
    'lateral_movement': 'T1021',
    'privilege_escalation': 'T1548',
    'defense_evasion': 'T1036',
}

SEVERITY_LEVELS = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}

def infer_severity(event_type):
    """Infer severity from event type."""
    critical_events = ['privilege_escalation', 'persistence', 'lateral_movement']
    high_events = ['process_creation', 'registry_modification']
    return 'CRITICAL' if event_type in critical_events else ('HIGH' if event_type in high_events else 'MEDIUM')

def generate_report(events, report_format='full'):
    """Generate structured behavior report."""
    if not events:
        return {'status': 'error', 'message': 'No events provided'}
    
    # Count severity levels
    severity_counts = Counter()
    for event in events:
        sev = event.get('severity', infer_severity(event.get('event_type', 'unknown')))
        severity_counts[sev] += 1
    
    # Extract unique sources
    sources = set(e.get('source', 'unknown') for e in events)
    
    # Sort by timestamp
    sorted_events = sorted(events, key=lambda e: e.get('timestamp', ''))
    time_range = {
        'first': sorted_events[0].get('timestamp', '') if sorted_events else '',
        'last': sorted_events[-1].get('timestamp', '') if sorted_events else ''
    }
    
    # MITRE mapping
    mitre_techs = defaultdict(int)
    for e in events:
        etype = e.get('event_type', 'unknown')
        if etype in MITRE_MAPPING:
            mitre_techs[MITRE_MAPPING[etype]] += 1
    
    # Timeline by hour
    timeline = defaultdict(list)
    for e in sorted_events:
        ts = e.get('timestamp', '')[:13]
        timeline[ts].append(e)
    
    # Critical/High events
    critical_high = [e for e in sorted_events 
                    if SEVERITY_LEVELS.get(e.get('severity', infer_severity(e.get('event_type'))), 0) >= 3]
    
    report = {
        'metadata': {
            'report_id': str(uuid.uuid4()),
            'generated_at': datetime.now().isoformat(),
            'analyst': socket.gethostname(),
            'tool_version': '1.0'
        },
        'executive_summary': {
            'total_events': len(events),
            'critical_count': severity_counts.get('CRITICAL', 0),
            'high_count': severity_counts.get('HIGH', 0),
            'medium_count': severity_counts.get('MEDIUM', 0),
            'low_count': severity_counts.get('LOW', 0),
            'unique_sources': len(sources),
            'time_range': time_range
        },
        'mitre_mapping': dict(mitre_techs),
        'top_indicators': dict(Counter(e.get('event_type') for e in events).most_common(5)),
        'findings': critical_high[:20] if report_format == 'full' else []
    }
    
    if report_format == 'summary':
        return {'metadata': report['metadata'], 'executive_summary': report['executive_summary']}
    
    return report

def main():
    p = argparse.ArgumentParser(description="Generate structured behavior reports with MITRE mapping")
    p.add_argument("--input", required=True, help="Input JSON file with events")
    p.add_argument("--output", help="Output JSON file")
    p.add_argument("--format", choices=['summary', 'full'], default='full', help="Report format")
    args = p.parse_args()
    
    try:
        with open(args.input) as f:
            data = json.load(f)
        
        events = data if isinstance(data, list) else data.get('events', [data])
        report = generate_report(events, args.format)
        
        print(f"[+] Behavior Report Generated")
        print(f"    Total events: {report['executive_summary']['total_events']}")
        print(f"    CRITICAL: {report['executive_summary']['critical_count']}")
        print(f"    HIGH: {report['executive_summary']['high_count']}")
        print(f"    Sources: {report['executive_summary']['unique_sources']}")
        print(f"    MITRE techniques: {len(report['mitre_mapping'])}")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[+] Report saved to {args.output}")
        else:
            print(json.dumps(report, indent=2))
        
        return 0
    except FileNotFoundError:
        print(f"Error: File not found", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        return 1
    except (IOError, KeyError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
