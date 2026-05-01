#!/usr/bin/env python3
"""Service Version Detector - Detects service versions and outdated software."""

import sys, socket, argparse, re, json

def banner_grab(host, port, timeout=5):
    """Grab service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        return banner
    except Exception as e:
        return None

def detect_version(banner):
    """Extract version from banner."""
    if not banner:
        return None
    
    patterns = [
        r'([0-9]+\.[0-9]+\.[0-9]+)',
        r'v([0-9]+\.[0-9]+)',
        r'Version[:\s]+([0-9.]+)',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, banner)
        if match:
            return match.group(1)
    return None

def check_outdated(service, version):
    """Check if version is known vulnerable."""
    known_vulnerable = {
        'Apache': ['2.2.0', '2.2.15'],
        'nginx': ['0.8.0', '1.0.0'],
        'OpenSSH': ['3.0', '4.0'],
    }
    
    return version in known_vulnerable.get(service, [])

def main():
    p = argparse.ArgumentParser(description="Detect service versions")
    p.add_argument("host", help="Hostname/IP")
    p.add_argument("--port", type=int, default=80, help="Port")
    p.add_argument("--ports", help="Comma-separated ports")
    p.add_argument("--output", help="Output JSON")
    args = p.parse_args()
    
    try:
        ports = [int(x) for x in args.ports.split(',')] if args.ports else [args.port]
        results = []
        
        for port in ports[:10]:
            banner = banner_grab(args.host, port)
            if banner:
                version = detect_version(banner)
                service_name = 'Unknown'
                if 'Apache' in banner: service_name = 'Apache'
                elif 'nginx' in banner: service_name = 'nginx'
                elif 'SSH' in banner: service_name = 'OpenSSH'
                
                is_vulnerable = check_outdated(service_name, version)
                
                results.append({
                    'port': port,
                    'service': service_name,
                    'version': version,
                    'banner': banner[:100],
                    'vulnerable': is_vulnerable
                })
        
        print(f"[+] Service Version Detection Report")
        print(f"    Host: {args.host}")
        print(f"    Services found: {len(results)}")
        
        for r in results:
            status = "[VULNERABLE]" if r['vulnerable'] else ""
            print(f"    Port {r['port']}: {r['service']} {r['version']} {status}")
        
        if args.output:
            json.dump(results, open(args.output, 'w'), indent=2)
        
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
