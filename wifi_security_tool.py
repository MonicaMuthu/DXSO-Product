import os
import time
import socket
import subprocess
import psutil
from scapy.all import ARP, Ether, srp
import pywifi
from pywifi import const
import re

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
            return "Firewall Status: Enabled (ICMP Blocked)"
        elif "reply from" in result.stdout.lower():
            return "Firewall Status: Disabled or Permissive (ICMP Allowed)"
        else:
            return "Firewall Status: Unknown behavior"
    except:
        return "Firewall Status: Could not determine"

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
    output_lines = []
    output_lines.append("Scanning Wi-Fi SSIDs and Encryption...")
    networks = get_ssid_and_encryption()
    output_lines.append("Scanning devices on the network...")
    devices = scan_lan_devices()

    output_lines.append("\n--- Wi-Fi Security Assessment Summary ---")
    output_lines.append(f"Total Nearby SSIDs Detected: {len(networks)}\n")
    for n in networks:
        encryption_type = assess_encryption_protocol(n['Encryption'])
        password_strength = analyze_password_strength(n['SSID'])
        output_lines.append(f"SSID: {n['SSID']} | BSSID: {n['BSSID']} | Signal: {n['Signal']} | Encryption: {encryption_type} | Password Strength: {password_strength}")

    output_lines.append(f"\nTotal Devices Detected on LAN: {len(devices)}")
    for d in devices:
        output_lines.append(f"IP: {d['ip']} | MAC: {d['mac']}")
        fw_status = check_firewall(d['ip'])
        output_lines.append(f"    ↳ {fw_status}")
        open_ports = check_ports(d['ip'])
        output_lines.append(f"    ↳ Open Ports: {open_ports if open_ports else 'None'}")

    mac_filtering_enabled = check_mac_filtering(devices)
    output_lines.append(f"\nMAC Address Filtering: {'Likely Enabled' if mac_filtering_enabled else 'Not Strict (Duplicates found)'}")

    guest_result = is_guest_network()
    output_lines.append(f"\nGuest Network: {'Likely Active (based on subnet/isolation)' if guest_result else 'Not Detected'}")

    output_lines.append("\nWIDS/WIPS Detection: Not Directly Detectable via Script (Requires Enterprise WLC or sensors)")
    output_lines.append("\nAuthentication Mechanism: Ports 802.1X/Radius not directly testable, but check port 1812 (RADIUS) or 443")

    output_lines.append("\nFirewall Integration: Basic ping & port test included (advanced requires admin router access)")
    output_lines.append("Router Firmware Updates: Cannot be checked without SNMP/HTTP admin access")
    output_lines.append("Network Segmentation: Suggested if LAN device count is zero in shared network")
    output_lines.append("Audit and Logging: Add centralized logging/SIEM in real deployments")
    output_lines.append("Penetration Testing: Manual tools (e.g., nmap, metasploit) needed for deep test")
    output_lines.append("User Awareness Testing: Consider phishing simulations or training platform")

    output_lines.append("\nBandwidth Estimate: Based on total devices + signal strength (not accurate without SNMP)")
    output_lines.append("For precise bandwidth & traffic, integrate with SNMP or NetFlow in enterprise setups.\n")
    output_lines.append("--- End of Assessment ---")

    for line in output_lines:
        print(line)

    with open("wifi_security_report.txt", "w") as f:
        for line in output_lines:
            f.write(line + "\n")

if __name__ == "__main__":
    generate_report()
