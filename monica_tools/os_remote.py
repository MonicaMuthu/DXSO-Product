import nmap
import socket
import subprocess
from datetime import datetime

def get_local_ip():
    result = subprocess.run("ipconfig", capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if "IPv4 Address" in line or "IPv4" in line:
            return line.split(":")[-1].strip()
    return None

def get_subnet(ip):
    try:
        parts = ip.split('.')
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return subnet
    except:
        return None

def scan_network(subnet, report_file):
    print(f"\n🔍 Scanning subnet: {subnet} ...")

    nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
    scanner = nmap.PortScanner(nmap_search_path=(nmap_path,))

    scanner.scan(hosts=subnet, arguments="-O -p 135,139,445,22,80,443 --host-timeout 30s")

    with open(report_file, "w", encoding="utf-8") as report:
        report.write(f"=== Network OS Activity Report ===\n")
        report.write(f"Scan Time: {datetime.now()}\n")
        report.write(f"Scanned Subnet: {subnet}\n")
        report.write("-" * 60 + "\n")

        for host in scanner.all_hosts():
            report.write(f"\n📡 Host: {host}\n")
            try:
                hostname = socket.gethostbyaddr(host)[0]
                report.write(f"  ↪ Hostname: {hostname}\n")
            except:
                report.write(f"  ↪ Hostname: Unknown\n")

            report.write(f"  ↪ State: {scanner[host].state()}\n")

            os_guesses = scanner[host].get('osmatch', [])
            if os_guesses:
                os = os_guesses[0]['name']
                report.write(f"  ↪ OS Guess: {os}\n")
            else:
                report.write("  ↪ OS Guess: Not Available\n")

            if 'tcp' in scanner[host]:
                report.write("  ↪ Open Ports:\n")
                for port in scanner[host]['tcp']:
                    service = scanner[host]['tcp'][port]['name']
                    report.write(f"     - Port {port} : {service}\n")
            else:
                report.write("  ↪ No open ports detected.\n")

    print(f"\n✅ Report saved to: {report_file}")


if __name__ == "__main__":
    print("=== Network OS Activity Scanner ===")
    local_ip = get_local_ip()
    if not local_ip:
        print("[!] Unable to detect local IP address.")
    else:
        subnet = get_subnet(local_ip)
        if subnet:
            report_filename = "os_detection_report.txt"
            scan_network(subnet, report_filename)
        else:
            print("[!] Failed to calculate subnet.")
