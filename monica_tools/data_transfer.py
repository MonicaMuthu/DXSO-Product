import os
import psutil
import time
import logging
from datetime import datetime
import socket

# === Setup Logging ===
if not os.path.exists("logs"):
    os.makedirs("logs")

logging.basicConfig(
    filename="logs/data_monitor.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

ALERT_LOG = "logs/alerts.txt"

def log_alert(message):
    with open(ALERT_LOG, "a") as f:
        f.write(f"[{datetime.now()}] ALERT: {message}\n")
    print(f"[ALERT] {message}")

# === 1. Data Flow Analysis ===
def data_flow():
    net_io = psutil.net_io_counters()
    logging.info(f"Data Flow - Sent: {net_io.bytes_sent} bytes, Received: {net_io.bytes_recv} bytes")
    return net_io.bytes_sent, net_io.bytes_recv

# === 2. File Transfer Monitoring ===
def monitor_transfers(sent, recv):
    total = sent + recv
    limit = 500 * 1024 * 1024  # 500 MB
    logging.info(f"File Transfer Monitor - Total Usage: {total / 1024 / 1024:.2f} MB")
    if total > limit:
        log_alert(f"High Data Usage Detected: {total / 1024 / 1024:.2f} MB")

# === 3. Protocol Identification (Simulated) ===
def identify_protocols():
    protocols = ["HTTP", "HTTPS", "DNS"]
    logging.info(f"Protocol Identification - Protocols Used: {', '.join(protocols)}")
    return protocols

# === 4. Bandwidth Utilization ===
def bandwidth_util():
    time.sleep(1)
    sent1, recv1 = data_flow()
    time.sleep(1)
    sent2, recv2 = data_flow()
    upload_speed = (sent2 - sent1) / 1024
    download_speed = (recv2 - recv1) / 1024
    logging.info(f"Bandwidth - Upload: {upload_speed:.2f} KB/s, Download: {download_speed:.2f} KB/s")

# === 5. Encrypted vs Unencrypted (Simulated by ports) ===
def check_encryption():
    encrypted_ports = [443, 22]
    unencrypted_ports = [80, 21]
    logging.info("Encrypted Connections: HTTPS, SSH")
    logging.info("Unencrypted Connections: HTTP, FTP")

# === 6. Unauthorized Transfers (Simulated Check) ===
def detect_unauthorized():
    suspicious_processes = ['filezilla.exe', 'utorrent.exe']
    found = False
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] in suspicious_processes:
            found = True
            log_alert(f"Unauthorized Transfer App Detected: {proc.info['name']} (PID {proc.info['pid']})")
    if not found:
        logging.info("Unauthorized Transfer - No suspicious apps found.")

# === 7. Data Transfer Limits ===
def check_limits(sent, recv):
    threshold = 100 * 1024 * 1024  # 100 MB
    logging.info(f"Data Transfer Limits - Upload: {sent} bytes, Download: {recv} bytes")
    if sent > threshold:
        log_alert("Upload exceeded limit.")
    if recv > threshold:
        log_alert("Download exceeded limit.")

# === 8. Real-Time Alerts Wrapper ===
def monitor_real_time():
    sent, recv = data_flow()
    monitor_transfers(sent, recv)
    check_limits(sent, recv)
    detect_unauthorized()

# === 9. DLP (Simple Keyword Detection) ===
def dlp_check():
    keywords = ["confidential", "password", "secret"]
    suspicious_files = []
    for root, dirs, files in os.walk("C:/Users", topdown=True):
        for name in files:
            if name.endswith(".txt") or name.endswith(".docx"):
                try:
                    with open(os.path.join(root, name), 'r', errors='ignore') as f:
                        content = f.read().lower()
                        if any(keyword in content for keyword in keywords):
                            suspicious_files.append(os.path.join(root, name))
                except:
                    continue
    if suspicious_files:
        logging.info(f"DLP - {len(suspicious_files)} suspicious files found.")
    else:
        logging.info("DLP - No sensitive data found.")
    for file in suspicious_files:
        log_alert(f"DLP Alert - Sensitive data found in {file}")

# === 10. Cross-Network Transfers ===
def cross_network_check():
    logging.info("Cross-Network Transfer - No unusual transfer detected (simulated).")

# === 11. Cloud Storage Monitoring (Simulated) ===
def cloud_storage_check():
    cloud_apps = ['Dropbox.exe', 'GoogleDrive.exe', 'OneDrive.exe']
    found = False
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] in cloud_apps:
            logging.info(f"Cloud Upload in Progress: {proc.info['name']}")
            found = True
    if not found:
        logging.info("Cloud Storage - No cloud upload activity found.")

# === 12. Audit and Logging ===
def audit_log():
    logging.info("Audit Check - Logging system is active and running.")

# === 13. Compliance Checks (Simulated File Check) ===
def compliance_check():
    required_files = ["privacy_policy.txt", "security_guidelines.txt"]
    passed = True
    for f in required_files:
        if not os.path.exists(f):
            passed = False
            log_alert(f"Compliance Check Failed: Missing {f}")
        else:
            logging.info(f"Compliance Check Passed: {f}")
    if passed:
        logging.info("Compliance Check - All required documents found.")

# === Historical Summary ===
def historical_summary():
    if os.path.exists("logs/data_monitor.log"):
        with open("logs/data_monitor.log", "r") as f:
            print("\n=== Historical Transfer Report (Last 10 lines) ===")
            for line in f.readlines()[-10:]:
                print(line.strip())
        logging.info("Historical Report - Displayed last 10 lines from log.")

# === Main Function ===
def main():
    print("🔍 Data Monitoring Script Started...")
    logging.info("=== Data Monitoring Session Started ===")

    sent, recv = data_flow()
    identify_protocols()
    bandwidth_util()
    check_encryption()
    monitor_real_time()
    cloud_storage_check()
    dlp_check()
    cross_network_check()
    audit_log()
    compliance_check()
    historical_summary()

    print("✅ Monitoring Completed. Check logs for details.")

if __name__ == "__main__":
    main()
