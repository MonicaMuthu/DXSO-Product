from scapy.all import *
from collections import defaultdict, Counter
import datetime
import threading
import time
import ipaddress

# === Global Stats ===
bandwidth_usage = defaultdict(int)
host_traffic_flow = defaultdict(lambda: defaultdict(int))
protocols_seen = set()
alerts = []
alert_types = defaultdict(list)
html_alert_lines = []

cloud_hosts = ["dropbox.com", "drive.google.com", "onedrive.live.com"]
unencrypted_ports = [80, 21]
encrypted_ports = [443, 22]

report_file = "dt_monitoring_report.html"
start_time = datetime.datetime.now()
MAX_ALERTS = 20  # ✅ Real-Time Alerts limit set to 20
cross_network_count = 0
unauth_transfer_count = 0
large_transfer_count = 0

local_ip = get_if_addr(conf.iface)
local_network = ipaddress.ip_network(local_ip + "/24", strict=False)

def process_packet(packet):
    global cross_network_count, unauth_transfer_count, large_transfer_count

    try:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            size = len(packet)

            # 1. Data Flow
            bandwidth_usage[ip_src] += size
            host_traffic_flow[ip_src][ip_dst] += size

            # 2. Protocol ID
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                dport = packet.dport
                proto = packet.sprintf('%IP.proto%')
                protocols_seen.add(proto)

                # 3. Encrypted/Unencrypted
                if dport in encrypted_ports:
                    log_event("Encrypted Transfer", ip_src, ip_dst)
                elif dport in unencrypted_ports:
                    raise_alert("Unencrypted Traffic", ip_src, ip_dst)

                # 4. Cross-network
                if ipaddress.ip_address(ip_src) not in local_network or ipaddress.ip_address(ip_dst) not in local_network:
                    if cross_network_count < 20:
                        raise_alert("Cross-Network Transfer", ip_src, ip_dst)
                        cross_network_count += 1

                # 5. Large File Transfer
                if "HTTP" in proto or dport in [21, 80]:
                    if size > 1_000_000 and large_transfer_count < 10:
                        raise_alert("Large File Transfer", ip_src, ip_dst)
                        large_transfer_count += 1

                # 6. Unauthorized Transfers
                if dport not in encrypted_ports + unencrypted_ports:
                    if unauth_transfer_count < 20:
                        raise_alert("Unauthorized Transfer", ip_src, ip_dst)
                        unauth_transfer_count += 1

                # 7. DLP Monitoring
                if b"password" in bytes(packet).lower() or b"confidential" in bytes(packet).lower():
                    raise_alert("DLP Violation", ip_src, ip_dst)

                # 8. Cloud Storage Monitoring
                for ch in cloud_hosts:
                    if ch in packet.summary().lower():
                        raise_alert(f"Cloud Upload Detected ({ch})", ip_src, ip_dst)

    except Exception:
        pass

def raise_alert(label, src, dst):
    if len(alerts) >= MAX_ALERTS:
        return
    timestamp = str(datetime.datetime.now())
    row = f"<tr><td>{timestamp}</td><td>{label}</td><td>{src}</td><td>{dst}</td></tr>"
    alerts.append(row)
    alert_types[label].append((src, dst))
    html_alert_lines.append(row)
    print(f"[ALERT] {label} from {src} to {dst} at {timestamp}")

def log_event(label, src, dst):
    timestamp = datetime.datetime.now()
    html_alert_lines.append(f"<tr><td>{timestamp}</td><td>{label}</td><td>{src}</td><td>{dst}</td></tr>")

def monitor_transfer_limits():
    while True:
        time.sleep(10)
        for ip, bw in bandwidth_usage.items():
            if bw > 50 * 1024 * 1024:
                raise_alert("Data Transfer Limit Exceeded (>50MB)", ip, "ANY")

def compliance_check():
    insecure = any(p.lower() in ["http", "ftp"] for p in protocols_seen)
    if insecure:
        alert_types["Compliance"].append("❌ Insecure protocols used (HTTP, FTP)")
    else:
        alert_types["Compliance"].append("✅ All data transfers used secure protocols")

def write_summary_report():
    duration = datetime.datetime.now() - start_time
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("<html><head><title>Network Monitoring Report</title>")
        f.write("<style>body{font-family:Arial} table{border-collapse:collapse;width:100%;margin-bottom:20px;} th,td{border:1px solid #ccc;padding:8px;} th{background:#f2f2f2;} h2{color:#333;} .ok{color:green;} .bad{color:red;}</style>")
        f.write("</head><body>")
        f.write("<h1>🛰️ Network Data Transfer Monitoring Report</h1>")
        f.write(f"<p><strong>Session Start:</strong> {start_time}</p>")
        f.write(f"<p><strong>Monitoring Duration:</strong> {duration}</p><hr>")

        # 1. Data Flow
        f.write("<h2>1. 📊 Data Flow Analysis</h2><table><tr><th>Source</th><th>Destination</th><th>KB</th></tr>")
        for src, dsts in host_traffic_flow.items():
            for dst, size in dsts.items():
                f.write(f"<tr><td>{src}</td><td>{dst}</td><td>{round(size/1024,2)}</td></tr>")
        f.write("</table>")

        # 2. File Transfer
        f.write("<h2>2. 📁 File Transfer Monitoring</h2>")
        transfers = alert_types.get("Large File Transfer", [])
        if transfers:
            f.write("<ul>" + "".join(f"<li>{src} → {dst}</li>" for src, dst in transfers) + "</ul>")
        else:
            f.write("<p class='ok'>✔️ No large file transfers detected.</p>")

        # 3. Protocols
        f.write("<h2>3. 🧩 Protocol Identification</h2>")
        if protocols_seen:
            f.write("<p>" + ", ".join(sorted(protocols_seen)) + "</p>")
        else:
            f.write("<p>No protocols captured.</p>")

        # 4. Bandwidth
        f.write("<h2>4. 📶 Bandwidth Utilization</h2><table><tr><th>IP</th><th>Total (MB)</th></tr>")
        for ip, bw in bandwidth_usage.items():
            f.write(f"<tr><td>{ip}</td><td>{round(bw/1024/1024,2)}</td></tr>")
        f.write("</table>")

        # 5. Encrypted vs Unencrypted
        f.write("<h2>5. 🔐 Encrypted vs Unencrypted Data</h2>")
        unenc = alert_types.get("Unencrypted Traffic", [])
        if unenc:
            f.write(f"<p class='bad'>❌ {len(unenc)} unencrypted sessions detected.</p>")
        else:
            f.write("<p class='ok'>✔️ All data used secure protocols.</p>")

        # 6. Unauthorized Transfers
        f.write("<h2>6. 🚫 Unauthorized Transfers</h2>")
        unauthed = alert_types.get("Unauthorized Transfer", [])
        if unauthed:
            f.write("<ul>" + "".join(f"<li>{src} → {dst}</li>" for src, dst in unauthed) + "</ul>")
        else:
            f.write("<p class='ok'>✔️ No unauthorized transfers.</p>")

        # 7. Data Limit
        f.write("<h2>7. 📈 Data Transfer Limits</h2>")
        exceeded = alert_types.get("Data Transfer Limit Exceeded (>50MB)", [])
        if exceeded:
            f.write("<ul>" + "".join(f"<li>{src}</li>" for src, _ in exceeded) + "</ul>")
        else:
            f.write("<p class='ok'>✔️ All hosts within safe data limits.</p>")

        # 8. Real-Time Alerts
        f.write("<h2>8. ⏱️ Real-Time Alerts</h2>")
        if html_alert_lines:
            f.write("<table><tr><th>Time</th><th>Type</th><th>Source</th><th>Destination</th></tr>")
            for alert in html_alert_lines:
                f.write(alert)
            f.write("</table>")
        else:
            f.write("<p>No alerts triggered.</p>")

        # 9. DLP
        f.write("<h2>9. 🛡️ Data Loss Prevention</h2>")
        dlp = alert_types.get("DLP Violation", [])
        if dlp:
            f.write("<ul>" + "".join(f"<li>{src} → {dst}</li>" for src, dst in dlp) + "</ul>")
        else:
            f.write("<p class='ok'>✔️ No DLP violations detected.</p>")

        # 10. Cross-Network
        f.write("<h2>10. 🌍 Cross-Network Transfers</h2>")
        cross = alert_types.get("Cross-Network Transfer", [])
        if cross:
            f.write("<ul>" + "".join(f"<li>{src} → {dst}</li>" for src, dst in cross) + "</ul>")
        else:
            f.write("<p class='ok'>✔️ All communication was internal.</p>")

        # 11. Cloud Monitoring
        f.write("<h2>11. ☁️ Cloud Storage Monitoring</h2>")
        cloud_found = False
        for ch in cloud_hosts:
            for key in alert_types.keys():
                if ch in key.lower():
                    f.write(f"<p class='bad'>⚠️ Uploads to {ch} detected.</p>")
                    cloud_found = True
        if not cloud_found:
            f.write("<p class='ok'>✔️ No cloud uploads detected.</p>")

        # 12. Audit Log already shown in alerts

        # 13. Compliance
        f.write("<h2>13. 📜 Compliance Checks</h2>")
        for line in alert_types["Compliance"]:
            f.write(f"<p>{line}</p>")

        # 14. Historical Summary
        f.write(f"<h2>14. 🧾 Historical Data Transfer Summary</h2><p>Total unique hosts: {len(bandwidth_usage)}</p>")

        # 15. Final Summary
        f.write("<h2>15. ✅ Summary</h2><p>Monitoring complete. Report saved as <strong>{}</strong>.</p>".format(report_file))

        f.write("</body></html>")

def start_monitoring():
    print("🛰️ Monitoring started... Writing to:", report_file)
    threading.Thread(target=monitor_transfer_limits, daemon=True).start()
    sniff(prn=process_packet, store=0, timeout=60)
    compliance_check()
    write_summary_report()

if __name__ == "__main__":
    try:
        start_monitoring()
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped by user. Writing summary...")
        compliance_check()
        write_summary_report()
