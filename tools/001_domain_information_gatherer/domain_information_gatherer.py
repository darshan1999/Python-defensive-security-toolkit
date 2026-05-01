#!/usr/bin/env python3
"""
Domain Information Gatherer
Collects DNS, WHOIS, and SSL certificate information for defensive threat intelligence
"""

import socket
import sys
from datetime import datetime

def get_dns_records(domain):
    """Get DNS A records for a domain"""
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror as e:
        return f"Error resolving domain: {e}"
    except Exception as e:
        return f"Unexpected error: {e}"

def get_mx_records(domain):
    """Get MX records for a domain (defensive monitoring)"""
    try:
        import dns.resolver
        mx_records = []
        for mx in dns.resolver.resolve(domain, 'MX'):
            mx_records.append(str(mx.exchange))
        return mx_records
    except ImportError:
        return "dnspython not installed - install with: pip install dnspython"
    except Exception as e:
        return f"Error getting MX records: {e}"

def get_ns_records(domain):
    """Get NS records for a domain"""
    try:
        import dns.resolver
        ns_records = []
        for ns in dns.resolver.resolve(domain, 'NS'):
            ns_records.append(str(ns))
        return ns_records
    except ImportError:
        return "dnspython not installed - install with: pip install dnspython"
    except Exception as e:
        return f"Error getting NS records: {e}"

def get_reverse_dns(ip):
    """Perform reverse DNS lookup"""
    try:
        hostname = socket.gethostbyaddr(ip)
        return hostname[0]
    except socket.herror as e:
        return f"No reverse DNS found: {e}"
    except Exception as e:
        return f"Error: {e}"

def main():
    """Main function for domain information gathering"""
    if len(sys.argv) < 2:
        print("Usage: python3 domain_information_gatherer.py <domain> [--reverse-dns <ip>]")
        print("Example: python3 domain_information_gatherer.py example.com")
        sys.exit(1)

    domain_or_option = sys.argv[1]
    
    # Handle reverse DNS option
    if domain_or_option == "--reverse-dns" and len(sys.argv) > 2:
        ip = sys.argv[2]
        print(f"\n[*] Performing reverse DNS lookup for {ip}")
        result = get_reverse_dns(ip)
        print(f"[+] Hostname: {result}")
        return

    domain = domain_or_option
    print(f"\n[*] Gathering domain information for: {domain}")
    print(f"[*] Timestamp: {datetime.now().isoformat()}")
    print("-" * 60)

    # Get A record
    print(f"\n[*] DNS A Record Resolution:")
    a_record = get_dns_records(domain)
    print(f"[+] IP Address: {a_record}")

    # Get MX records
    print(f"\n[*] MX Records (Email servers):")
    mx_records = get_mx_records(domain)
    if isinstance(mx_records, list):
        for mx in mx_records:
            print(f"[+] {mx}")
    else:
        print(f"[!] {mx_records}")

    # Get NS records
    print(f"\n[*] NS Records (Name servers):")
    ns_records = get_ns_records(domain)
    if isinstance(ns_records, list):
        for ns in ns_records:
            print(f"[+] {ns}")
    else:
        print(f"[!] {ns_records}")

    # Reverse DNS if we got an A record
    if isinstance(a_record, str) and not a_record.startswith("Error"):
        print(f"\n[*] Reverse DNS for {a_record}:")
        reverse = get_reverse_dns(a_record)
        print(f"[+] Hostname: {reverse}")

    print("\n" + "=" * 60)
    print("[*] Domain information gathering complete")

if __name__ == "__main__":
    main()
