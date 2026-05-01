"""
Manual Port Scanning With Python Sockets

Security operations automation tool.
"""

import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2)
result = sock.connect_ex(("example.com", 80))
if result == 0:
    print("Port 80 is open")
else:
    print("Port 80 is closed or filtered")
sock.close()
import socket
def scan_ports(target, port_list, timeout=1):
    open_ports = []
    for port in port_list:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"[+] Port {port} is open")
                open_ports.append(port)
            else:
                print(f"[-] Port {port} is closed or filtered")
            sock.close()
        except Exception as e:
            print(f"[!] Error scanning port {port}: {e}")
    return open_ports
target_host = "scanme.nmap.org"
ports_to_scan = list(range(20, 1025))  # Common ports
found_ports = scan_ports(target_host, ports_to_scan)
print("Open ports found:", found_ports)
import socket
import threading
open_ports = []
lock = threading.Lock()
def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            with lock:
                print(f"[+] Port {port} is open")
                open_ports.append(port)
    except:
        pass
def threaded_scan(target, ports):
    threads = []
    for port in ports:
        t = threading.Thread(target=scan_port, args=(target, port))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    return open_ports
target = "scanme.nmap.org"
ports = range(1, 1025)
results = threaded_scan(target, ports)
print("Scan complete. Open ports:", results)
def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        banner = s.recv(1024)
        s.close()
        return banner.decode(errors='ignore')
    except:
        return None
ip = "scanme.nmap.org"
for port in [21, 22, 80]:
    banner = grab_banner(ip, port)
    if banner:
        print(f"Banner from port {port}:\n{banner}")
import json
from datetime import datetime
def save_results(host, open_ports):
    report = {
        "host": host,
        "timestamp": datetime.utcnow().isoformat(),
        "open_ports": open_ports
    }
    with open("scan_results.json", "w") as f:
        json.dump(report, f, indent=2)
save_results("scanme.nmap.org", [22, 80, 443])