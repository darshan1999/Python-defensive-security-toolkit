#!/usr/bin/env python3
"""Multi-Format IOC Exporter - Exports IOCs to STIX, OpenIOC, MISP, or text formats."""

import sys, json, csv, xml.etree.ElementTree as ET, argparse
from datetime import datetime

def export_stix(iocs, out):
    bundle = {'type': 'bundle', 'id': f'bundle--{datetime.now().isoformat()}', 'objects': []}
    for ioc in iocs:
        t = ioc.get('type', '').lower()
        v = ioc.get('value', '')
        patterns = {'ip': f"[ipv4-addr:value = '{v}']", 'domain': f"[domain-name:value = '{v}']",
                   'hash': f"[file:hashes.MD5 = '{v}']", 'url': f"[url:value = '{v}']"}
        bundle['objects'].append({'type': 'indicator', 'pattern': patterns.get(t, v),
                                  'labels': ['malicious-activity'], 'created': datetime.now().isoformat()})
    json.dump(bundle, open(out, 'w'), indent=2)
    return True

def export_misp(iocs, out):
    with open(out, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['Event', 'Type', 'Value', 'Comment'])
        w.writeheader()
        for i in iocs:
            w.writerow({'Event': f"IOC-{datetime.now().strftime('%Y%m%d')}", 'Type': i.get('type'),
                       'Value': i.get('value'), 'Comment': i.get('tags', '')})
    return True

def export_xml(iocs, out):
    root = ET.Element('OpenIOC')
    for ioc in iocs:
        ind = ET.SubElement(root, 'Indicator')
        ET.SubElement(ind, 'Type').text = ioc.get('type', '')
        ET.SubElement(ind, 'Value').text = ioc.get('value', '')
    ET.ElementTree(root).write(out)
    return True

def export_txt(iocs, out):
    grouped = {}
    for i in iocs:
        t = i.get('type', 'unknown')
        grouped.setdefault(t, []).append(i.get('value', ''))
    with open(out, 'w') as f:
        for t, vals in grouped.items():
            f.write(f"# {t.upper()}\n" + "\n".join(vals) + "\n\n")
    return True

def main():
    p = argparse.ArgumentParser(description="Export IOCs to multiple formats")
    p.add_argument("input", help="Input JSON file")
    p.add_argument("--format", choices=['stix', 'xml', 'misp', 'txt', 'all'], default='txt')
    p.add_argument("--output", help="Output file")
    args = p.parse_args()
    
    try:
        iocs = json.load(open(args.input))
        if not isinstance(iocs, list): iocs = [iocs]
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    exporters = {'stix': export_stix, 'xml': export_xml, 'misp': export_misp, 'txt': export_txt}
    success = False
    
    if args.format == 'all':
        base = args.output or 'iocs'
        success = all([exporters[fmt](iocs, f'{base}.{fmt}{"" if fmt != "xml" else ""}')
                      for fmt in ['stix', 'xml', 'misp', 'txt']])
    else:
        out = args.output or f'iocs.{args.format}'
        success = exporters[args.format](iocs, out)
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
