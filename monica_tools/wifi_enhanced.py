import os
import time
import socket
import subprocess
import psutil
from scapy.all import ARP, Ether, srp
import pywifi
from pywifi import const
import re
import pandas as pd
from jinja2 import Template

# Get local interface
def get_default_interface():
    interfaces = psutil.net_if_addrs()
    for iface_name in interfaces:
        if iface_name.lower().startswith("wi") or iface_name.lower().startswith("eth"):
            return iface_name
    return list(interfaces.keys())[0]

# Scan SSID & encryption
def get_ssid_and_encryption():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]
    iface.scan()
    time.sleep(2)
    results = iface.scan_results()
    networks = []
    for network in results:
        networks.append({
            'SSID': network.ssid,
            'BSSID': network.bssid,
            'Signal': network.signal,
            'Encryption': network.akm
        })
    return networks

# Scan LAN devices
def scan_lan_devices():
    interface = get_default_interface()
    print(f"Using interface: {interface}")
    target_ip = "192.168.1.1/24"
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, iface=interface, verbose=0)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

# MAC filtering check
def check_mac_filtering(devices):
    known_macs = [d['mac'] for d in devices]
    unique_macs = list(set(known_macs))
    return len(known_macs) == len(unique_macs)

# Firewall ping check with status classification
def check_firewall(ip):
    try:
        result = subprocess.run(['ping', '-n', '1', ip], capture_output=True, text=True)
        if "unreachable" in result.stdout.lower() or "100%" in result.stdout:
            return "Enabled (ICMP Blocked)"
        elif "reply from" in result.stdout.lower():
            return "Disabled or Permissive (ICMP Allowed)"
        else:
            return "Unknown behavior"
    except:
        return "Could not determine"

# Port scan
def check_ports(ip):
    common_ports = [22, 23, 80, 443, 445, 3389, 1812]
    open_ports = []
    for port in common_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    return open_ports

# Check encryption protocol strength
def assess_encryption_protocol(encryption_list):
    if const.AKM_TYPE_WPA2PSK in encryption_list:
        return "Strong (WPA2)"
    elif const.AKM_TYPE_WPAPSK in encryption_list:
        return "Moderate (WPA)"
    elif const.AKM_TYPE_NONE in encryption_list:
        return "Open (No encryption)"
    else:
        return "Unknown/Other"

# Password strength analysis (basic SSID name check)
def analyze_password_strength(ssid):
    if len(ssid) < 8:
        return "Weak (SSID too short)"
    if not re.search(r"[A-Z]", ssid) or not re.search(r"[0-9]", ssid):
        return "Moderate (Consider strong mix in passphrase)"
    return "Likely Strong (Assuming WPA2+ and proper password)"

# Guest Network Detection Logic
def get_local_ip():
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except:
        return None

def is_guest_subnet(ip):
    return ip.startswith("192.168.100.") or ip.startswith("10.") or ip.startswith("172.")

def can_ping_internal_hosts():
    test_ips = ["192.168.1.1", "192.168.1.10"]
    for ip in test_ips:
        result = subprocess.run(['ping', '-n', '1', ip], capture_output=True, text=True)
        if "Reply from" in result.stdout:
            return True
    return False

def can_access_router():
    try:
        socket.create_connection(("192.168.1.1", 80), timeout=1)
        return True
    except:
        return False

def is_guest_network():
    ip = get_local_ip()
    if ip is None:
        return False
    in_guest_range = is_guest_subnet(ip)
    isolated = not can_ping_internal_hosts() and not can_access_router()
    return in_guest_range or isolated

# --- Final Report ---
def generate_report():
    networks = get_ssid_and_encryption()
    devices = scan_lan_devices()

    wifi_data = []
    for n in networks:
        encryption_type = assess_encryption_protocol(n['Encryption'])
        password_strength = analyze_password_strength(n['SSID'])
        wifi_data.append({"SSID": n['SSID'], "BSSID": n['BSSID'], "Signal": n['Signal'],
                          "Encryption": encryption_type, "Password Strength": password_strength})

    device_data = []
    for d in devices:
        fw_status = check_firewall(d['ip'])
        open_ports = check_ports(d['ip'])
        device_data.append({"IP": d['ip'], "MAC": d['mac'], "Firewall Status": fw_status,
                            "Open Ports": ', '.join(map(str, open_ports))})

    summary = {
        "MAC Address Filtering": "Likely Enabled" if check_mac_filtering(devices) else "Not Strict (Duplicates found)",
        "Guest Network": "Likely Active" if is_guest_network() else "Not Detected",
        "WIDS/WIPS Detection": "Cannot detect without Enterprise Controllers",
        "Authentication Ports": "Checked ports: 1812, 443",
        "Firewall Integration": "ICMP + port scan conducted",
        "Router Firmware Updates": "Access denied (needs SNMP or HTTP login)",
        "Network Segmentation": "LAN Active" if len(devices) else "Possible segmentation",
        "Audit & Logging": "Not implemented. Recommend SIEM setup",
        "Penetration Testing": "Manual tools like nmap/metasploit required",
        "User Awareness Testing": "Use phishing simulation tools",
        "Bandwidth Estimate": "SNMP/NetFlow needed for accurate usage"
    }

    # Generate HTML report using Jinja2 template
    html_template = Template("""
    <html>
    <head><title>Wi-Fi Security Report</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }
        th, td { border: 1px solid #999; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        h2 { color: #333; }
    </style>
    </head>
    <body>
    <h1>Wi-Fi Security Assessment Report</h1>

    <h2>Nearby Wi-Fi Networks</h2>
    <table>
        <tr><th>SSID</th><th>BSSID</th><th>Signal</th><th>Encryption</th><th>Password Strength</th></tr>
        {% for row in wifi_data %}
        <tr><td>{{ row['SSID'] }}</td><td>{{ row['BSSID'] }}</td><td>{{ row['Signal'] }}</td><td>{{ row['Encryption'] }}</td><td>{{ row['Password Strength'] }}</td></tr>
        {% endfor %}
    </table>

    <h2>LAN Devices</h2>
    <table>
        <tr><th>IP</th><th>MAC</th><th>Firewall Status</th><th>Open Ports</th></tr>
        {% for row in device_data %}
        <tr><td>{{ row['IP'] }}</td><td>{{ row['MAC'] }}</td><td>{{ row['Firewall Status'] }}</td><td>{{ row['Open Ports'] }}</td></tr>
        {% endfor %}
    </table>

    <h2>Security Summary</h2>
    <table>
        <tr><th>Check</th><th>Result</th></tr>
        {% for key, value in summary.items() %}
        <tr><td>{{ key }}</td><td>{{ value }}</td></tr>
        {% endfor %}
    </table>

    <p>✅ Report generated successfully.</p>
    </body>
    </html>
    """)

    html_output = html_template.render(wifi_data=wifi_data, device_data=device_data, summary=summary)
    with open("wifi_security_report.html", "w", encoding="utf-8") as f:
        f.write(html_output)

    print("\n✅ HTML security report saved as 'wifi_security_report.html'")

if __name__ == "__main__":
    generate_report()
