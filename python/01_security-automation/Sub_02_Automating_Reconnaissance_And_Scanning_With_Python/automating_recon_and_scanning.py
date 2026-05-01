"""
Automating Recon And Scanning

Security operations automation tool.
"""

import subprocess
target = "scanme.nmap.org"
ports = "22,80,443"
command = ["nmap", "-Pn", "-sS", "-p", ports, target]
result = subprocess.run(command, capture_output=True, text=True)
print(result.stdout)
import xml.etree.ElementTree as ET
tree = ET.parse("output.xml")
root = tree.getroot()
for host in root.findall("host"):
    ip = host.find("address").get("addr")
    print(f"Host: {ip}")
    # Get open ports
    for port in host.findall("ports/port"):
        port_id = port.get("portid")
        protocol = port.get("protocol")
        state = port.find("state").get("state")
        service = port.find("service").get("name", "unknown")
        print(f" - Port {port_id}/{protocol}: {state} ({service})")
import socket
def scan_ports(target, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Short timeout for speed
        result = sock.connect_ex((target, port))  # 0 means open
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports
target_host = "scanme.nmap.org"
ports_to_test = [22, 80, 443, 8080]
open_found = scan_ports(target_host, ports_to_test)
print(f"Open ports on {target_host}: {open_found}")
import requests
ip = "8.8.8.8"
response = requests.get(f"https://ipinfo.io/{ip}/json")
if response.status_code == 200:
    data = response.json()
    print("IP Info:")
    print(f" - City: {data.get('city')}")
    print(f" - Org: {data.get('org')}")
    print(f" - ASN: {data.get('asn', {}).get('asn', 'N/A')}")
import subprocess
import socket
import xml.etree.ElementTree as ET
def run_nmap(target, ports):
    xml_out = "temp.xml"
    command = ["nmap", "-Pn", "-sS", "-p", ports, target, "-oX", xml_out]
    subprocess.run(command)
    return xml_out
def parse_nmap(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    report = []
    for host in root.findall("host"):
        ip = host.find("address").get("addr")
        for port in host.findall("ports/port"):
            port_id = port.get("portid")
            state = port.find("state").get("state")
            service = port.find("service").get("name", "unknown")
            report.append((ip, port_id, state, service))
    return report
def quick_socket_scan(target, ports):
    found = []
    for port in ports:
        s = socket.socket()
        s.settimeout(1)
        if s.connect_ex((target, port)) == 0:
            found.append(port)
        s.close()
    return found
host = "scanme.nmap.org"
nmap_result = run_nmap(host, "22,80,443")
parsed_data = parse_nmap(nmap_result)
print("[+] Nmap XML Parsed:")
for row in parsed_data:
    print(row)
print("[+] Socket scan result:", quick_socket_scan(host, [22, 80, 443]))