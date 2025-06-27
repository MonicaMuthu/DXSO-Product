import nmap
import socket
import subprocess
from datetime import datetime
import winrm

def get_local_ip():
    result = subprocess.run("ipconfig", capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if "IPv4" in line:
            return line.split(":")[-1].strip()
    return None

def get_subnet(ip):
    try:
        parts = ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except:
        return None

def get_patch_info(ip, user, password):
    try:
        session = winrm.Session(ip, auth=(user, password))
        result = session.run_cmd('wmic qfe list brief')
        return result.std_out.decode().strip()
    except Exception as e:
        return f"[ERROR] Unable to fetch patches: {e}"

def get_installed_software(ip, user, password):
    try:
        session = winrm.Session(ip, auth=(user, password))
        result = session.run_cmd('wmic product get name,version')
        return result.std_out.decode().strip()
    except Exception as e:
        return f"[ERROR] Unable to fetch software inventory: {e}"

def scan_network(subnet, html_file, user, password):
    scanner = nmap.PortScanner(nmap_search_path=(r"C:\Program Files (x86)\Nmap\nmap.exe",))
    scanner.scan(hosts=subnet, arguments="-O -p 135,139,445,22,80,443,5985 --host-timeout 30s")

    with open(html_file, "w", encoding="utf-8") as report:
        report.write(f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>OS Detection Report</title>
<style>
body {{ font-family: Arial; background: #f5f5f5; padding: 20px; }}
h1 {{ color: #2c3e50; }}
pre {{ background: #fff; border: 1px solid #ccc; padding: 10px; overflow-x: auto; }}
.host {{ border: 2px solid #3498db; padding: 10px; margin-bottom: 15px; background: #ecf0f1; }}
</style></head><body>
<h1>🧠 Full Network OS Security Audit Report</h1>
<p><strong>Scan Time:</strong> {datetime.now()}</p>
<p><strong>Scanned Subnet:</strong> {subnet}</p><hr>
""")

        for host in scanner.all_hosts():
            report.write(f'<div class="host">\n<h2>📡 Host: {host}</h2>\n')
            try:
                hostname = socket.gethostbyaddr(host)[0]
                report.write(f"<p><strong>Hostname:</strong> {hostname}</p>\n")
            except:
                report.write(f"<p><strong>Hostname:</strong> Unknown</p>\n")

            report.write(f"<p><strong>State:</strong> {scanner[host].state()}</p>\n")

            os_guesses = scanner[host].get('osmatch', [])
            if os_guesses:
                os = os_guesses[0]['name']
                report.write(f"<p><strong>OS Identification:</strong> {os}</p>\n")
            else:
                report.write("<p><strong>OS Identification:</strong> Not Available</p>\n")

            if scanner[host].has_tcp(5985):
                report.write("<h3>🔧 Patch Level Assessment</h3><pre>")
                patches = get_patch_info(host, user, password)
                report.write(patches + "</pre>\n")

                report.write("<h3>📦 Installed Software Inventory</h3><pre>")
                software = get_installed_software(host, user, password)
                report.write(software + "</pre>\n")

                report.write("<h3>🛡️ Vulnerability Detection</h3><ul>")
                if "KB" in patches:
                    for line in patches.splitlines():
                        if "KB" in line:
                            report.write(f"<li>✅ Checked: {line.strip()}</li>\n")
                else:
                    report.write("<li>No KBs found to evaluate.</li>\n")
                report.write("</ul>\n")
            else:
                report.write("<p>⚠️ Skipping Patch/Vuln/Software: WinRM not enabled.</p>\n")

            if 'tcp' in scanner[host]:
                report.write("<h3>🔓 Open Ports</h3><ul>")
                for port in scanner[host]['tcp']:
                    service = scanner[host]['tcp'][port]['name']
                    report.write(f"<li>Port {port} : {service}</li>\n")
                report.write("</ul>\n")
            else:
                report.write("<p>No open ports detected.</p>\n")
            report.write("</div>\n")

        report.write("</body></html>")

    print(f"\n✅ HTML report saved to: {html_file}")


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
            html_filename = "os_detection_report.html"
            scan_network(subnet, html_filename, username, password)
        else:
            print("[!] Failed to determine subnet.")
