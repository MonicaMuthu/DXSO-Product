import os
import json
import re
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime, timedelta, timezone
from jinja2 import Environment, FileSystemLoader

# === CONFIGURATION ===
LOG_PATH = "/var/log/suricata/eve.json"
REPORT_DIR = "./full_traffic_report"
os.makedirs(REPORT_DIR, exist_ok=True)

MAX_LINES = 5000
TIME_WINDOW_MINUTES = 60
CUTOFF_TIME = datetime.now(timezone.utc) - timedelta(minutes=TIME_WINDOW_MINUTES)


# === HELPERS ===

def is_ipv4(ip):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip or "") is not None


def tail_log(path, lines=MAX_LINES):
    with open(path, 'rb') as f:
        f.seek(0, os.SEEK_END)
        size, data = f.tell(), b""
        while size > 0 and data.count(b'\n') < lines:
            read_size = min(4096, size)
            f.seek(size - read_size)
            data = f.read(read_size) + data
            size -= read_size
        return data.decode(errors='ignore').splitlines()[-lines:]


def parse_logs():
    records = []
    for line in tail_log(LOG_PATH):
        try:
            event = json.loads(line)
            ts = event.get("timestamp") or event.get("flow", {}).get("start")
            dt = pd.to_datetime(ts, utc=True, errors='coerce')
            if pd.isnull(dt) or dt < CUTOFF_TIME:
                continue
            src_ip = event.get("src_ip")
            dest_ip = event.get("dest_ip")
            if not is_ipv4(src_ip) or not is_ipv4(dest_ip):
                continue
            records.append({
                "timestamp": dt,
                "event_type": event.get("event_type"),
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "proto": event.get("proto"),
                "app_proto": event.get("app_proto"),
                "alert": event.get("alert", {}).get("signature"),
                "bytes_toserver": event.get("flow", {}).get("bytes_toserver"),
                "bytes_toclient": event.get("flow", {}).get("bytes_toclient")
            })
        except:
            continue
    return pd.DataFrame(records)


def generate_bandwidth_graph(df):
    df = df.copy()
    df.set_index('timestamp', inplace=True)
    df['total_bytes'] = df[['bytes_toserver', 'bytes_toclient']].fillna(0).sum(axis=1)
    df_b = df['total_bytes'].resample('1Min').sum()
    path = os.path.join(REPORT_DIR, "bandwidth.png")
    plt.figure(figsize=(8, 3))
    df_b.plot()
    plt.title("Bandwidth Usage (Last 60 min)")
    plt.ylabel("Bytes")
    plt.xlabel("Time")
    plt.grid()
    plt.tight_layout()
    plt.savefig(path)
    plt.close()
    return "bandwidth.png"


def generate_congestion_graph(df):
    df = df.copy()
    df.set_index('timestamp', inplace=True)
    df['total_bytes'] = df[['bytes_toserver', 'bytes_toclient']].fillna(0).sum(axis=1)
    df_b = df['total_bytes'].resample('1Min').sum()
    threshold = df_b.max() * 0.8
    congested = df_b > threshold
    path = os.path.join(REPORT_DIR, "congestion.png")
    plt.figure(figsize=(8, 3))
    df_b.plot(label="Usage")
    plt.fill_between(df_b.index, 0, df_b, where=congested, color='red', alpha=0.3, label="Congested")
    plt.axhline(threshold, color='orange', linestyle='--', label="80% Threshold")
    plt.title("Network Congestion Analysis")
    plt.legend()
    plt.grid()
    plt.tight_layout()
    plt.savefig(path)
    plt.close()
    return "congestion.png"


def summarize(df):
    sections = []

    flows = df[df['event_type'] == 'flow']
    alerts = df[df['alert'].notna()]
    protocols = df['proto'].value_counts().head(10).to_dict()
    app_protocols = df['app_proto'].dropna().value_counts().head(10).to_dict()
    src_ips = df['src_ip'].value_counts().head(10).to_dict()
    dest_ips = df['dest_ip'].value_counts().head(10).to_dict()
    alert_counts = alerts['alert'].value_counts().head(10).to_dict()

    def fmt_section(title, content_dict):
        html = f"<h3>{title}</h3><ul>"
        for k, v in content_dict.items():
            html += f"<li><b>{k}:</b> {v}</li>"
        return html + "</ul>"

    sections.append(fmt_section("1. Protocol Analysis", protocols))
    sections.append(fmt_section("2. Application Traffic Analysis", app_protocols))
    sections.append(fmt_section("3. Top Source IPs", src_ips))
    sections.append(fmt_section("4. Top Destination IPs", dest_ips))
    sections.append(fmt_section("5. Real-Time Alerts (Top Signatures)", alert_counts))
    sections.append(f"<h3>6. Total Flows</h3><p>{len(flows)}</p>")

    return sections


def generate_html_report(sections, bw_graph, con_graph, total_events):
    env = Environment(loader=FileSystemLoader('.'))
    tmpl = env.from_string("""
    <html>
    <head>
        <title>Enterprise Network Traffic Summary</title>
        <style>
            body {
                font-family: 'Segoe UI', Roboto, sans-serif;
                background: #f0f2f5;
                margin: 0;
                padding: 0;
            }
            .container {
                max-width: 1100px;
                margin: auto;
                padding: 30px;
            }
            .card {
                background: #ffffff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                border-radius: 10px;
                margin-bottom: 30px;
                padding: 25px;
            }
            h1, h2, h3 {
                color: #2c3e50;
            }
            .header-box {
                background: #006eff;
                color: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                margin-bottom: 30px;
            }
            .header-box h1 {
                margin: 0;
                font-size: 28px;
            }
            .graph {
                text-align: center;
                margin-top: 10px;
                margin-bottom: 20px;
            }
            ul {
                padding-left: 20px;
            }
            li {
                margin-bottom: 5px;
                font-size: 15px;
            }
            footer {
                text-align: center;
                font-size: 13px;
                color: gray;
                margin-top: 40px;
            }
        </style>
    </head>
    <body>
        <div class="container">

            <div class="header-box">
                <h1>🚀 Enterprise Network Traffic Summary</h1>
                <p><strong>Time Window:</strong> Last 60 minutes</p>
                <p><strong>Total Events:</strong> {{ total }}</p>
            </div>

            <div class="card">
                <h2>📊 Bandwidth Usage</h2>
                <div class="graph"><img src="{{ bw_graph }}" width="95%"></div>
            </div>

            <div class="card">
                <h2>🚦 Network Congestion</h2>
                <div class="graph"><img src="{{ con_graph }}" width="95%"></div>
            </div>

            {% for section in sections %}
            <div class="card">
                {{ section | safe }}
            </div>
            {% endfor %}

            <footer>
                Report generated by <strong>Suricata Summary Tool</strong> | {{ total }} Events
            </footer>

        </div>
    </body>
    </html>
    """)
    html = tmpl.render(sections=sections, total=total_events, bw_graph=bw_graph, con_graph=con_graph)
    with open(os.path.join(REPORT_DIR, "summary_report.html"), "w") as f:
        f.write(html)


def generate_json_summary(df):
    summary = {
        "events": len(df),
        "top_src_ips": df['src_ip'].value_counts().head(10).to_dict(),
        "top_dest_ips": df['dest_ip'].value_counts().head(10).to_dict(),
        "protocols": df['proto'].value_counts().to_dict(),
        "application_protocols": df['app_proto'].dropna().value_counts().to_dict(),
        "alerts": df['alert'].dropna().value_counts().to_dict()
    }
    with open(os.path.join(REPORT_DIR, "summary_report.json"), "w") as f:
        json.dump(summary, f, indent=2)


# === MAIN ===

df_logs = parse_logs()
if df_logs.empty:
    print("⚠ No recent data available.")
else:
    bw = generate_bandwidth_graph(df_logs)
    cg = generate_congestion_graph(df_logs)
    sections = summarize(df_logs)
    generate_html_report(sections, bw, cg, len(df_logs))
    generate_json_summary(df_logs)
    print("✅ Summarized report generated successfully.")
