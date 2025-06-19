import subprocess
import socket
from scapy.all import ARP, Ether, srp, conf, get_if_list
from pywifi import PyWiFi
import time

def scan_wifi():
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]
    iface.scan()
    time.sleep(2)
    results = iface.scan_results()
    ssids = []
    for network in results:
        ssid = network.ssid if network.ssid else "<Hidden>"
        bssid = network.bssid
        signal = network.signal
        encryption = "WPA2" if network.akm else "Open"
        ssids.append((ssid, bssid, signal, encryption))
    return ssids

def get_interface():
    interfaces = get_if_list()
    for iface in interfaces:
        if "Wi-Fi" in iface or "wlan" in iface.lower():
            return iface
    return conf.iface

def scan_lan_devices(interface):
    ip_range = ".".join(socket.gethostbyname(socket.gethostname()).split(".")[:3]) + ".1/24"
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, iface=interface, verbose=0)[0]
    return [{"ip": rcv.psrc, "mac": rcv.hwsrc} for _, rcv in result]

def is_guest_network(ssids, devices):
    isolation = len(devices) == 0
    guest_ssid = any("guest" in ssid.lower() for ssid, _, _, _ in ssids)
    return isolation or guest_ssid

def detect_wids_wips():
    return "Not directly detectable via script. Requires enterprise-grade sensors."

def analyze_ap_placement(ssids):
    placement = {}
    for ssid, bssid, signal, _ in ssids:
        if bssid not in placement or signal > placement[bssid]:
            placement[bssid] = signal
    return placement

def detect_firewall_block():
    try:
        socket.create_connection(("192.168.1.1", 80), timeout=2)
        return "Firewall: Router port 80 accessible"
    except:
        return "Firewall: Router access likely blocked"

def estimate_bandwidth(devices, ssids):
    signals = [s for _, _, s, _ in ssids]
    avg = sum(signals) / len(signals) if signals else -100
    return f"Devices: {len(devices)}, Signal Avg: {avg:.2f} dBm (SNMP required for actual bandwidth)"

def detect_authentication():
    try:
        output = subprocess.check_output("netstat -an", shell=True).decode()
        if ":1812" in output:
            return "802.1X/RADIUS Detected (Port 1812)"
        elif ":443" in output:
            return "Captive Portal Likely (Port 443 open)"
        return "No strong auth mechanism detected"
    except:
        return "Unable to determine authentication"

def generate_report():
    ssids = scan_wifi()
    interface = get_interface()
    devices = scan_lan_devices(interface)

    lines = []
    lines.append("Scanning Wi-Fi SSIDs and Encryption...")
    lines.append("Scanning devices on the network...")
    lines.append(f"Using interface: {interface}\n")

    lines.append("--- Wi-Fi Security Assessment Summary ---")
    lines.append(f"Total Nearby SSIDs Detected: {len(ssids)}\n")
    for ssid, bssid, signal, encryption in ssids:
        lines.append(f"SSID: {ssid} | BSSID: {bssid} | Signal: {signal} | Encryption: {encryption}")
    
    lines.append(f"\nTotal Devices Detected on LAN: {len(devices)}")
    lines.append("MAC Address Filtering: " + ("Likely Enabled" if len(devices) == 0 else "Possibly Disabled"))
    lines.append("Guest Network: " + ("Likely Guest" if is_guest_network(ssids, devices) else "Trusted Network"))
    lines.append("WIDS/WIPS Detection: " + detect_wids_wips())

    lines.append("\nAccess Point Placement (Signal Strengths):")
    placements = analyze_ap_placement(ssids)
    for bssid, signal in placements.items():
        lines.append(f"  AP BSSID: {bssid} | Signal: {signal} dBm")

    lines.append("\nFirewall Integration: " + detect_firewall_block())
    lines.append("Bandwidth Estimate: " + estimate_bandwidth(devices, ssids))
    lines.append("Authentication Mechanism: " + detect_authentication())
    lines.append("\n--- End of Assessment ---")

    # Print to console
    for line in lines:
        print(line)

    # Save to file
    with open("wifi_security_report.txt", "w") as f:
        f.write("\n".join(lines))
    print("\n📄 Report saved as 'wifi_security_report.txt'")

if __name__ == "__main__":
    generate_report()
