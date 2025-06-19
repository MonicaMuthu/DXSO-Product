import subprocess
import os
from datetime import datetime
import time

log_file = ""

def log_output(text):
    print(text)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(text + "\n")

def capture_live_traffic(interface, duration=10):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = f"audit_logs/live_capture_{timestamp}.pcapng"
    log_output(f"\n[+] Capturing live traffic from '{interface}' for {duration} seconds...")
    subprocess.run([
        "dumpcap",
        "-i", interface,
        "-a", f"duration:{duration}",
        "-w", pcap_file
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log_output(f"[✓] Live traffic captured to: {pcap_file}")
    return pcap_file

def analyze_tls(pcap_file):
    log_output("\n[1] TLS Encryption & Cipher Assessment")

    tls_versions = subprocess.run([
        "tshark", "-r", pcap_file,
        "-Y", "tls",
        "-T", "fields", "-e", "tls.record.version"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    ciphers = subprocess.run([
        "tshark", "-r", pcap_file,
        "-Y", "tls.handshake.ciphersuite",
        "-T", "fields", "-e", "tls.handshake.ciphersuite"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    certs = subprocess.run([
        "tshark", "-r", pcap_file,
        "-Y", "x509sat.printableString",
        "-T", "fields", "-e", "x509sat.printableString"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    log_output(f"TLS Versions:\n{tls_versions.stdout.strip() or 'No TLS versions found.'}\n")
    log_output(f"Cipher Suites:\n{ciphers.stdout.strip() or 'No cipher suites found.'}\n")
    log_output(f"Certificates:\n{certs.stdout.strip() or 'No certificates found.'}")

    if tls_versions.stderr or ciphers.stderr or certs.stderr:
        log_output("[!] Errors:")
        log_output(tls_versions.stderr)
        log_output(ciphers.stderr)
        log_output(certs.stderr)

def get_firewall_status():
    log_output("\n[3] Firewall Status")
    fw_status = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    log_output(fw_status.stdout)

def monitor_traffic_live(interface):
    log_output("\n[4] Real-Time Traffic Monitor")
    for _ in range(5):
        cmd = [
            "powershell", "-Command",
            f"$counter = Get-Counter '\\\\Network Interface({interface})\\\\Bytes Total/sec'; " +
            "$bytes = [math]::Round($counter.CounterSamples[0].CookedValue); " +
            '$mbps = [math]::Round($bytes / 125000, 2); ' +
            'Write-Output "$(Get-Date -Format HH:mm:ss) `t`t B/s $bytes `t $mbps Mbps"'
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        log_output(result.stdout.strip())
        time.sleep(2)

def list_recent_logons():
    log_output("\n[5] Recent Logins")
    powershell_script = (
        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 5 | "
        "ForEach-Object { $_.Properties[4].Value + ' ' + $_.Properties[8].Value + ' ' + $_.TimeCreated }"
    )
    result = subprocess.run(["powershell", "-Command", powershell_script],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    log_output(result.stdout.strip())

def main():
    global log_file
    os.makedirs("audit_logs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"audit_logs/wifi_audit_{timestamp}.log"

    print("\n========== Wi-Fi Security & Traffic Assessment ==========\n")

    # Step 1: Ask for Wi-Fi adapter name
    interface_name = input("Enter your Wi-Fi adapter name (e.g., Wi-Fi, Wi-Fi 2, Intel...): ").strip()

    # Step 2: Capture live traffic
    capture_file = capture_live_traffic(interface_name, duration=10)

    # Step 3: TLS & Cipher Analysis
    analyze_tls(capture_file)

    # Step 4: Firewall Status
    get_firewall_status()

    # Step 5: Live Traffic Monitor
    monitor_traffic_live(interface_name)

    # Step 6: Logon Events
    list_recent_logons()

    log_output(f"\n[✓] All tasks completed. Log saved at: {log_file}")

if __name__ == "__main__":
    main()
