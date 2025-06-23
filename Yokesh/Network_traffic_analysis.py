import json
import os
import pandas as pd
import matplotlib.pyplot as plt
from jinja2 import Environment, FileSystemLoader

# Configuration
EVE_LOG_PATH = "/var/log/suricata/eve.json"
REPORT_DIR = "./suricata_reports"
os.makedirs(REPORT_DIR, exist_ok=True)
MAX_ROWS = 20

parsed_data = []

# Step 1: Parse Suricata Logs
def parse_log():
    with open(EVE_LOG_PATH, 'r') as f:
        for line in f:
            try:
                event = json.loads(line)
                record = {
                    "timestamp": event.get("timestamp") or event.get("flow", {}).get("start"),
                    "event_type": event.get("event_type"),
                    "src_ip": event.get("src_ip"),
                    "dest_ip": event.get("dest_ip"),
                    "proto": event.get("proto"),
                    "app_proto": event.get("app_proto"),
                    "bytes_toserver": None,
                    "bytes_toclient": None,
                    "alert_signature": None
                }
                if event["event_type"] == "flow":
                    record["bytes_toserver"] = event["flow"].get("bytes_toserver")
                    record["bytes_toclient"] = event["flow"].get("bytes_toclient")
                if event["event_type"] == "alert":
                    record["alert_signature"] = event["alert"].get("signature")
                parsed_data.append(record)
            except json.JSONDecodeError:
                continue

# Step 2A: Bandwidth Graph
def generate_bandwidth_graph(df):
    if 'timestamp' not in df.columns:
        return None
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df.dropna(subset=['timestamp'], inplace=True)
    df.set_index('timestamp', inplace=True)
    df['bytes_total'] = df[['bytes_toserver', 'bytes_toclient']].fillna(0).sum(axis=1)
    df_resampled = df['bytes_total'].resample('1Min').sum()

    graph_path = os.path.join(REPORT_DIR, "bandwidth_graph.png")
    plt.figure(figsize=(10, 4))
    df_resampled.plot()
    plt.title("Bandwidth Usage Over Time")
    plt.ylabel("Bytes per minute")
    plt.xlabel("Time")
    plt.grid()
    plt.tight_layout()
    plt.savefig(graph_path)
    plt.close()
    return "bandwidth_graph.png"

# Step 2B: Congestion Graph
def generate_congestion_graph(df):
    if 'timestamp' not in df.columns:
        return None
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df.dropna(subset=['timestamp'], inplace=True)
    df.set_index('timestamp', inplace=True)
    df['bytes_total'] = df[['bytes_toserver', 'bytes_toclient']].fillna(0).sum(axis=1)
    df_resampled = df['bytes_total'].resample('1Min').sum()

    max_usage = df_resampled.max()
    threshold = max_usage * 0.8
    congested = df_resampled > threshold

    graph_path = os.path.join(REPORT_DIR, "congestion_graph.png")
    plt.figure(figsize=(10, 4))
    df_resampled.plot(label="Usage")
    plt.fill_between(df_resampled.index, 0, df_resampled,
                     where=congested,
                     color='red', alpha=0.4, label="Possible Congestion")
    plt.axhline(y=threshold, color='orange', linestyle='--', label="80% Threshold")
    plt.title("Network Congestion Analysis (Red = Suspected Congestion)")
    plt.ylabel("Bytes per minute")
    plt.xlabel("Time")
    plt.legend()
    plt.grid()
    plt.tight_layout()
    plt.savefig(graph_path)
    plt.close()
    return "congestion_graph.png"

# Helper: Safe Table Renderer
def render_table(dataframe, columns):
    valid_columns = [col for col in columns if col in dataframe.columns]
    if not valid_columns:
        return "<p>No data available (required columns missing).</p>"
    df_cut = dataframe[valid_columns].dropna(how='all').head(MAX_ROWS)
    if df_cut.empty:
        return "<p>No data to display.</p>"
    return df_cut.to_html(index=False)

# Step 3: Generate HTML Report
def generate_html_report(df, bandwidth_graph, congestion_graph):
    env = Environment(loader=FileSystemLoader('.'))
    template = env.from_string("""
    <html>
    <head>
        <title>Suricata Network Traffic Analysis Report</title>
        <style>
            body { font-family: Arial; margin: 30px; background-color: #f9f9f9; }
            h2 { color: #2e4053; margin-top: 30px; }
            .section { background: #fff; padding: 20px; border-radius: 10px; margin-bottom: 25px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 8px; font-size: 14px; }
            th { background-color: #eee; }
        </style>
    </head>
    <body>
        <h1>Suricata Network Traffic Analysis Report</h1>
        {% for section in sections %}
        <div class="section">
            <h2>📌 {{ section.title }}</h2>
            {{ section.content | safe }}
        </div>
        {% endfor %}
    </body>
    </html>
    """)

    df_dpi = df[df["alert_signature"].notna()]
    df_flow = df[df["event_type"] == "flow"]
    df_tls = df[df["app_proto"] == "tls"]
    df_scan = df[df["alert_signature"].str.contains("scan", case=False, na=False)]

    sections = [
        {
            "title": "Traffic Flow Monitoring",
            "content": render_table(df_flow, ["timestamp", "src_ip", "dest_ip", "proto", "bytes_toserver", "bytes_toclient"])
        },
        {
            "title": "Protocol Analysis",
            "content": render_table(df, ["timestamp", "proto", "app_proto"])
        },
        {
            "title": "Packet Inspection (DPI",
            "content": render_table(df_dpi, ["timestamp", "src_ip", "dest_ip", "alert_signature"])
        },
        {
            "title": "Traffic Anomaly Detection",
            "content": render_table(df_dpi, ["timestamp", "src_ip", "dest_ip", "alert_signature"])
        },
        {
            "title": "Bandwidth Utilization",
            "content": f'<img src="{bandwidth_graph}" width="800px">' if bandwidth_graph else "<p>Graph not available.</p>"
        },
        {
            "title": "Application Traffic Analysis",
            "content": render_table(df[df["app_proto"].notna()], ["timestamp", "src_ip", "dest_ip", "app_proto"])
        },
        {
            "title": "Traffic Classification",
            "content": render_table(df[df["app_proto"].notna()], ["timestamp", "app_proto", "src_ip", "dest_ip"])
        },
        {
            "title": "Real-Time Traffic Alerts",
            "content": render_table(df_dpi, ["timestamp", "src_ip", "dest_ip", "alert_signature"])
        },
        {
            "title": "IP Address Tracking",
            "content": render_table(df, ["timestamp", "src_ip", "dest_ip"])
        },
        {
            "title": "Port Scanning Detection",
            "content": render_table(df_scan, ["timestamp", "src_ip", "dest_ip", "alert_signature"])
        },
        {
            "title": "Latency and Jitter Analysis",
            "content": "<p><i>Not supported by Suricata. Use `ping` or `fping` for this activity.</i></p>"
        },
        {
            "title": "Traffic Logging",
            "content": render_table(df, ["timestamp", "event_type", "src_ip", "dest_ip"])
        },
        {
            "title": "Network Congestion Analysis",
            "content": f'<img src="{congestion_graph}" width="800px">' if congestion_graph else "<p>Graph not available.</p>"
        },
        {
            "title": "Encrypted Traffic Analysis",
            "content": render_table(df_tls, ["timestamp", "src_ip", "dest_ip", "proto", "app_proto"])
        },
        {
            "title": "Historical Traffic Reports",
            "content": render_table(df, ["timestamp", "src_ip", "dest_ip", "proto", "app_proto", "alert_signature"])
        },
    ]

    html_output = template.render(sections=sections)
    html_path = os.path.join(REPORT_DIR, "suricata_report.html")
    with open(html_path, "w") as f:
        f.write(html_output)
    print(f"[✅] HTML Report saved: {html_path}")

# MAIN
if __name__ == "__main__":
    print("[🔍] Parsing Suricata Logs...")
    parse_log()
    df = pd.DataFrame(parsed_data)

    print("[📈] Generating Bandwidth Graph...")
    bandwidth_graph = generate_bandwidth_graph(df.copy())  # ✅ use copy

    print("[📉] Generating Congestion Graph...")
    congestion_graph = generate_congestion_graph(df.copy())  # ✅ use copy

    print("[📄] Creating HTML Report...")
    generate_html_report(df, bandwidth_graph, congestion_graph)

