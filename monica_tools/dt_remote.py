from scapy.all import *
from collections import defaultdict, Counter
import datetime
import threading
import time

# === Global Stats ===
bandwidth_usage = defaultdict(int)
protocols_seen = set()
alerts = []
alert_types = defaultdict(list)
cloud_hosts = ["dropbox.com", "drive.google.com", "onedrive.live.com"]
unencrypted_ports = [80, 21]
encrypted_ports = [443, 22]
local_ip_prefix = ".".join(get_if_addr(conf.iface).split(".")[:3])
report_file = "dt_monitoring_report.txt"
start_time = datetime.datetime.now()

# === Alert Control ===
MAX_ALERTS = 20
cross_network_count = 0
unauth_transfer_count = 0

# === Packet Handler ===
def process_packet(packet):
    global cross_network_count, unauth_transfer_count

    try:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            size = len(packet)

            # 1. Data Flow Analysis
            bandwidth_usage[ip_src] += size

            # 3. Protocol Identification
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                sport = packet.sport
                dport = packet.dport
                proto = packet.sprintf('%IP.proto%')
                protocols_seen.add(proto)

                # 5. Encrypted vs Unencrypted Data
                if dport in encrypted_ports:
                    log_event("Encrypted transfer", ip_src, ip_dst)
                elif dport in unencrypted_ports:
                    raise_alert("Unencrypted Traffic", ip_src, ip_dst)

                # 10. Cross-Network Transfers
                if not ip_dst.startswith(local_ip_prefix) and cross_network_count < 25:
                    raise_alert("Cross-Network Transfer", ip_src, ip_dst)
                    cross_network_count += 1

                # 2. File Transfer Monitoring (Large)
                if "HTTP" in proto or dport in [21, 80]:
                    if size > 1000000:
                        raise_alert("Large File Transfer", ip_src, ip_dst)

                # 6. Unauthorized Transfers
                if dport not in encrypted_ports + unencrypted_ports and unauth_transfer_count < 25:
                    raise_alert("Unauthorized Transfer", ip_src, ip_dst)
                    unauth_transfer_count += 1

                # 9. DLP - simple keyword detection
                if b"password" in bytes(packet).lower() or b"confidential" in bytes(packet).lower():
                    raise_alert("DLP Violation", ip_src, ip_dst)

                # 11. Cloud Storage Monitoring
                for ch in cloud_hosts:
                    if ch in packet.summary().lower():
                        raise_alert(f"Cloud Upload Detected ({ch})", ip_src, ip_dst)

    except Exception:
        pass

# === Alerting ===
def raise_alert(label, src, dst):
    if len(alerts) >= MAX_ALERTS:
        return  # Limit total alerts

    timestamp = str(datetime.datetime.now())
    full_msg = f"[ALERT] {label} from {src} to {dst} at {timestamp}"
    alerts.append(full_msg)
    alert_types[label].append((src, dst))
    print(full_msg)
    with open(report_file, "a", encoding="utf-8") as f:
        f.write(full_msg + "\n")

def log_event(label, src, dst):
    with open(report_file, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.datetime.now()}] {label}: {src} → {dst}\n")

# === 7. Data Transfer Limits
def monitor_transfer_limits():
    while True:
        time.sleep(10)
        for ip, bw in bandwidth_usage.items():
            if bw > 50 * 1024 * 1024:
                raise_alert("Data Transfer Limit Exceeded (>50MB)", ip, "ANY")

# === 12. Compliance Checks
def compliance_check():
    insecure = any(p in protocols_seen for p in ["HTTP", "FTP"])
    if insecure:
        alert_types["Compliance"].append("❌ Insecure protocols used (HTTP, FTP)")
    else:
        alert_types["Compliance"].append("✅ All data transfers used secure protocols")

# === 13. Final Summary Report ===
def write_summary_report():
    duration = datetime.datetime.now() - start_time
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("=== 🛰️ Network Data Transfer Monitoring Report ===\n")
        f.write(f"Session Start: {start_time}\n")
        f.write(f"Monitoring Duration: {duration}\n")
        f.write("=" * 60 + "\n\n")

        f.write("📋 Monitoring Activity Breakdown:\n\n")

        # 1. Data Flow Analysis
        f.write("1. 📊 Data Flow Analysis:\n")
        for ip, bw in bandwidth_usage.items():
            f.write(f"   - {ip}: {round(bw / 1024, 2)} KB\n")
        f.write("\n")

        # 2. File Transfer Monitoring
        file_transfers = alert_types.get("Large File Transfer", [])
        if file_transfers:
            f.write(f"2. 🗂️ File Transfer Monitoring:\n   ⚠️ {len(file_transfers)} large transfers detected.\n")
            for src, dst in file_transfers[:3]:
                f.write(f"   → {src} → {dst}\n")
        else:
            f.write("2. 🗂️ File Transfer Monitoring:\n   ✔️ No large file transfers detected.\n")
        f.write("\n")

        # 3. Protocol Identification
        f.write("3. 🔄 Protocol Identification:\n")
        f.write("   Detected Protocols: " + ", ".join(protocols_seen) + "\n\n")

        # 4. Bandwidth Utilization
        top = sorted(bandwidth_usage.items(), key=lambda x: x[1], reverse=True)[:5]
        f.write("4. 📈 Bandwidth Utilization:\n")
        for ip, usage in top:
            f.write(f"   - {ip}: {round(usage / (1024 * 1024), 2)} MB\n")
        f.write("\n")

        # 5. Encrypted vs Unencrypted Data
        unenc = alert_types.get("Unencrypted Traffic", [])
        f.write("5. 🔐 Encrypted vs Unencrypted Data:\n")
        if unenc:
            f.write(f"   ⚠️ {len(unenc)} unencrypted transfers detected.\n")
            for src, dst in unenc[:3]:
                f.write(f"   → {src} → {dst}\n")
        else:
            f.write("   ✔️ All transfers used encrypted channels.\n")
        f.write("\n")

        # 6. Unauthorized Transfers
        unauth = alert_types.get("Unauthorized Transfer", [])
        f.write("6. 🚫 Unauthorized Transfers:\n")
        if unauth:
            f.write(f"   ⚠️ {len(unauth)} unauthorized transfers detected.\n")
            for src, dst in unauth[:3]:
                f.write(f"   → {src} → {dst}\n")
        else:
            f.write("   ✔️ No unauthorized transfers detected.\n")
        f.write("\n")

        # 7. Data Transfer Limits
        limits = alert_types.get("Data Transfer Limit Exceeded (>50MB)", [])
        f.write("7. 📏 Data Transfer Limits:\n")
        if limits:
            f.write(f"   ⚠️ {len(limits)} IPs exceeded transfer limits.\n")
            for src, dst in limits[:3]:
                f.write(f"   → {src} → {dst}\n")
        else:
            f.write("   ✔️ No IPs exceeded 50MB transfer limit.\n")
        f.write("\n")

        # 8. Real-Time Alerts
        f.write("8. ⏱️ Real-Time Alerts:\n")
        f.write(f"   Total Alerts Triggered: {len(alerts)} (max displayed: {MAX_ALERTS})\n\n")

        # 9. Data Loss Prevention (DLP)
        dlp = alert_types.get("DLP Violation", [])
        f.write("9. 🛑 Data Loss Prevention:\n")
        if dlp:
            f.write(f"   ⚠️ {len(dlp)} sensitive content detections.\n")
            for src, dst in dlp[:3]:
                f.write(f"   → {src} → {dst}\n")
        else:
            f.write("   ✔️ No DLP violations detected.\n")
        f.write("\n")

        # 10. Cross-Network Transfers
        cross = alert_types.get("Cross-Network Transfer", [])
        f.write("10. 🌐 Cross-Network Transfers:\n")
        if cross:
            f.write(f"   ⚠️ {len(cross)} external communications found.\n")
            for src, dst in cross[:3]:
                f.write(f"   → {src} → {dst}\n")
        else:
            f.write("   ✔️ No cross-network transfers.\n")
        f.write("\n")

        # 11. Cloud Storage Monitoring
        cloud = [k for k in alert_types if k.startswith("Cloud Upload Detected")]
        f.write("11. ☁️ Cloud Storage Monitoring:\n")
        if cloud:
            for label in cloud:
                entries = alert_types[label]
                f.write(f"   ⚠️ {len(entries)} uploads to {label.split('(')[-1][:-1]}.\n")
                for src, dst in entries[:3]:
                    f.write(f"   → {src} → {dst}\n")
        else:
            f.write("   ✔️ No cloud upload attempts found.\n")
        f.write("\n")

        # 12. Audit and Logging
        f.write("12. 🧾 Audit and Logging:\n")
        f.write(f"   - Total Alerts: {len(alerts)}\n")
        f.write(f"   - Protocols: {', '.join(protocols_seen)}\n")
        f.write(f"   - Top IPs monitored: {len(bandwidth_usage)}\n\n")

        # 13. Compliance Checks
        f.write("13. 📋 Compliance Checks:\n")
        if "Compliance" in alert_types:
            for item in alert_types["Compliance"]:
                f.write(f"   → {item}\n")
        else:
            f.write("   ✔️ No compliance issues detected.\n")
        f.write("\n")

        # Final Section
        f.write("✅ Monitoring completed. Summary generated.\n")
        f.write(f"📄 Report saved as: {report_file}\n")

# === Start Monitoring ===
def start_monitoring():
    print("🛰️ Monitoring started... Writing to:", report_file)
    threading.Thread(target=monitor_transfer_limits, daemon=True).start()
    sniff(prn=process_packet, store=0, timeout=60)  # Run for 60 seconds
    compliance_check()
    write_summary_report()

if __name__ == "__main__":
    try:
        start_monitoring()
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped by user. Writing summary...")
        compliance_check()
        write_summary_report()
