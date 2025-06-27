# import nmap
# import socket
# import subprocess
# from datetime import datetime

# def get_local_ip():
#     result = subprocess.run("ipconfig", capture_output=True, text=True)
#     for line in result.stdout.splitlines():
#         if "IPv4 Address" in line or "IPv4" in line:
#             return line.split(":")[-1].strip()
#     return None

# def get_subnet(ip):
#     try:
#         parts = ip.split('.')
#         subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
#         return subnet
#     except:
#         return None

# def scan_network(subnet, report_file):
#     print(f"\n🔍 Scanning subnet: {subnet} ...")

#     nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
#     scanner = nmap.PortScanner(nmap_search_path=(nmap_path,))

#     scanner.scan(hosts=subnet, arguments="-O -p 135,139,445,22,80,443 --host-timeout 30s")

#     with open(report_file, "w", encoding="utf-8") as report:
#         report.write(f"=== Network OS Activity Report ===\n")
#         report.write(f"Scan Time: {datetime.now()}\n")
#         report.write(f"Scanned Subnet: {subnet}\n")
#         report.write("-" * 60 + "\n")

#         for host in scanner.all_hosts():
#             report.write(f"\n📡 Host: {host}\n")
#             try:
#                 hostname = socket.gethostbyaddr(host)[0]
#                 report.write(f"  ↪ Hostname: {hostname}\n")
#             except:
#                 report.write(f"  ↪ Hostname: Unknown\n")

#             report.write(f"  ↪ State: {scanner[host].state()}\n")

#             os_guesses = scanner[host].get('osmatch', [])
#             if os_guesses:
#                 os = os_guesses[0]['name']
#                 report.write(f"  ↪ OS Guess: {os}\n")
#             else:
#                 report.write("  ↪ OS Guess: Not Available\n")

#             if 'tcp' in scanner[host]:
#                 report.write("  ↪ Open Ports:\n")
#                 for port in scanner[host]['tcp']:
#                     service = scanner[host]['tcp'][port]['name']
#                     report.write(f"     - Port {port} : {service}\n")
#             else:
#                 report.write("  ↪ No open ports detected.\n")

#     print(f"\n✅ Report saved to: {report_file}")


# if __name__ == "__main__":
#     print("=== Network OS Activity Scanner ===")
#     local_ip = get_local_ip()
#     if not local_ip:
#         print("[!] Unable to detect local IP address.")
#     else:
#         subnet = get_subnet(local_ip)
#         if subnet:
#             report_filename = "os_detection_report.txt"
#             scan_network(subnet, report_filename)
#         else:
#             print("[!] Failed to calculate subnet.")


import nmap
import socket
import subprocess
from datetime import datetime
import winrm

# Get local IP
def get_local_ip():
    result = subprocess.run("ipconfig", capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if "IPv4" in line:
            return line.split(":")[-1].strip()
    return None

# Calculate subnet
def get_subnet(ip):
    try:
        parts = ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except:
        return None

# Get patch info from remote Windows system
def get_patch_info(ip, user, password):
    try:
        session = winrm.Session(ip, auth=(user, password))
        result = session.run_cmd('wmic qfe list brief')
        return result.std_out.decode().strip()
    except Exception as e:
        return f"[ERROR] Unable to fetch patches: {e}"

# Get software inventory from remote Windows system
def get_installed_software(ip, user, password):
    try:
        session = winrm.Session(ip, auth=(user, password))
        result = session.run_cmd('wmic product get name,version')
        return result.std_out.decode().strip()
    except Exception as e:
        return f"[ERROR] Unable to fetch software inventory: {e}"

# Scan network and write results
def scan_network(subnet, report_file, user, password):
    print(f"\n🔍 Scanning subnet: {subnet} ...")

    nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
    scanner = nmap.PortScanner(nmap_search_path=(nmap_path,))
    scanner.scan(hosts=subnet, arguments="-O -p 135,139,445,22,80,443,5985 --host-timeout 30s")

    with open(report_file, "w", encoding="utf-8") as report:
        report.write("=== Full Network OS Security Audit Report ===\n")
        report.write(f"Scan Time: {datetime.now()}\n")
        report.write(f"Scanned Subnet: {subnet}\n")
        report.write("-" * 70 + "\n")

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
                report.write(f"  ↪ OS Identification: {os}\n")
            else:
                report.write("  ↪ OS Identification: Not Available\n")

            if scanner[host].has_tcp(5985):  # WinRM open
                report.write("  🔧 Patch Level Assessment:\n")
                patches = get_patch_info(host, user, password)
                report.write(patches + "\n")

                report.write("  📦 Installed Software Inventory:\n")
                software = get_installed_software(host, user, password)
                report.write(software + "\n")

                report.write("  🛡️ Vulnerability Detection:\n")
                if "KB" in patches:
                    for line in patches.splitlines():
                        if "KB" in line:
                            report.write(f"    - [✓] Checked: {line.strip()}\n")
                else:
                    report.write("    - No KBs found to evaluate.\n")
            else:
                report.write("  ⚠️ Skipping Patch/Vuln/Software: WinRM not enabled.\n")

            if 'tcp' in scanner[host]:
                report.write("  ↪ Open Ports:\n")
                for port in scanner[host]['tcp']:
                    service = scanner[host]['tcp'][port]['name']
                    report.write(f"     - Port {port} : {service}\n")
            else:
                report.write("  ↪ No open ports detected.\n")

            report.write("-" * 70 + "\n")

    print(f"\n✅ Report saved to: {report_file}")

# Main function
if __name__ == "__main__":
    print("=== Network OS Detection & Vulnerability Report Tool ===")
    username = input("Enter admin username for remote hosts: ")
    password = input("Enter password: ")

    local_ip = get_local_ip()
    if not local_ip:
        print("[!] Could not detect local IP.")
    else:
        subnet = get_subnet(local_ip)
        if subnet:
            report_file = "os_detection_report.txt"
            scan_network(subnet, report_file, username, password)
        else:
            print("[!] Failed to determine subnet.")
