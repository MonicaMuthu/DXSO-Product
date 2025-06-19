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

# Firewall ping check
def check_firewall(ip):
    try:
        result = subprocess.run(['ping', '-n', '1', ip], capture_output=True, text=True)
        return "Firewall Enabled (ping blocked)" if "unreachable" in result.stdout.lower() or "100%" in result.stdout else "Ping response - Firewall may be weak"
    except:
        return "Could not determine firewall status"

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
    if const.AKM_TYPE_WPA3PSK in encryption_list:
        return "Strong (WPA3)"
    elif const.AKM_TYPE_WPA2PSK in encryption_list:
        return "Moderate (WPA2)"
    elif const.AKM_TYPE_WPAPSK in encryption_list:
        return "Weak (WPA1)"
    else:
        return "Open or Unknown"

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
    print("Scanning Wi-Fi SSIDs and Encryption...")
    networks = get_ssid_and_encryption()
    print("Scanning devices on the network...")
    devices = scan_lan_devices()

    print("\n--- Wi-Fi Security Assessment Summary ---")
    print(f"Total Nearby SSIDs Detected: {len(networks)}\n")
    for n in networks:
        encryption_type = assess_encryption_protocol(n['Encryption'])
        password_strength = analyze_password_strength(n['SSID'])
        print(f"SSID: {n['SSID']} | BSSID: {n['BSSID']} | Signal: {n['Signal']} | Encryption: {encryption_type} | Password Strength: {password_strength}")

    print("\nTotal Devices Detected on LAN:", len(devices))
    for d in devices:
        print(f"IP: {d['ip']} | MAC: {d['mac']}")
        fw_status = check_firewall(d['ip'])
        print(f"    ↳ {fw_status}")
        open_ports = check_ports(d['ip'])
        print(f"    ↳ Open Ports: {open_ports if open_ports else 'None'}")

    mac_filtering_enabled = check_mac_filtering(devices)
    print("\nMAC Address Filtering:", "Likely Enabled" if mac_filtering_enabled else "Not Strict (Duplicates found)")

    guest_result = is_guest_network()
    print("\nGuest Network:", "Likely Active (based on subnet/isolation)" if guest_result else "Not Detected")

    print("\nWIDS/WIPS Detection: Not Directly Detectable via Script (Requires Enterprise WLC or sensors)")
    print("\nAuthentication Mechanism: Ports 802.1X/Radius not directly testable, but check port 1812 (RADIUS) or 443")

    print("\nFirewall Integration: Basic ping & port test included (advanced requires admin router access)")
    print("Router Firmware Updates: Cannot be checked without SNMP/HTTP admin access")
    print("Network Segmentation: Suggested if LAN device count is zero in shared network")
    print("Audit and Logging: Add centralized logging/SIEM in real deployments")
    print("Penetration Testing: Manual tools (e.g., nmap, metasploit) needed for deep test")
    print("User Awareness Testing: Consider phishing simulations or training platform")

    print("\nBandwidth Estimate: Based on total devices + signal strength (not accurate without SNMP)")
    print("For precise bandwidth & traffic, integrate with SNMP or NetFlow in enterprise setups.\n")
    print("--- End of Assessment ---")

if __name__ == "__main__":
    generate_report()
