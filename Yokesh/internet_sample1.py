import os
import subprocess
import json
import socket
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
import plotly.graph_objs as go

# Patch: Avoid optional import error in plotly
import sys
sys.modules['IPython'] = type(sys)('IPython')
sys.modules['IPython'].core = type(sys)('core')
sys.modules['IPython'].core.display = type(sys)('display')

# Constants
REPORT_DIR = Path("./monitoring_report")
REPORT_DIR.mkdir(parents=True, exist_ok=True)
HTML_REPORT = REPORT_DIR / "report_latest.html"
NOW = datetime.now()
PAST_TIME = NOW - timedelta(hours=4)

# Helper: Run shell command
def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True).strip()
    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {cmd}\n{e}")
        return ""

# Get local IP
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

LOCAL_IP = get_local_ip()
print("[+] Local IP:", LOCAL_IP)

# Auto-detect best network interface (prefer eth0, exclude docker/veth/lo)
def get_best_interface():
    try:
        interfaces = run("ls /sys/class/net").splitlines()
        candidates = []
        for iface in interfaces:
            if iface.startswith("docker") or iface.startswith("veth") or iface == "lo":
                continue
            state = run(f"cat /sys/class/net/{iface}/operstate")
            if state == "up":
                candidates.append(iface)
        if "eth0" in candidates:
            return "eth0"
        return candidates[0] if candidates else "eth0"
    except:
        return "eth0"

INTERFACE = get_best_interface()
print("[+] Using interface:", INTERFACE)

# Firefox internal telemetry domains to exclude
internal_domains = [
    "contile.services.mozilla.com", "push.services.mozilla.com",
    "firefox.settings.services.mozilla.com", "shavar.services.mozilla.com",
    "normandy.cdn.mozilla.net", "ads-img.mozilla.org",
    "content-signature-2.cdn.mozilla.net"
]

# Step 1: Extract Squid Access Logs (past 4 hours)
print("[+] Extracting Squid logs...")
squid_log = "/var/log/squid/access.log"
squid_lines = run(f"sudo cat {squid_log}").splitlines()
squid_summary = {}
filtered_domains = {}
squid_acl_rules = run("sudo grep -E '^(acl|http_access)' /etc/squid/squid.conf")

for line in squid_lines:
    parts = line.split()
    if len(parts) < 7:
        continue
    try:
        timestamp = datetime.fromtimestamp(float(parts[0]))
        if timestamp < PAST_TIME:
            continue
        domain = parts[6].split("/")[-1].split(":")[0].replace("http://", "").replace("https://", "")
        if domain and domain not in internal_domains:
            squid_summary[domain] = squid_summary.get(domain, 0) + 1
        if "DENIED" in line:
            filtered_domains[domain] = filtered_domains.get(domain, 0) + 1
    except:
        continue

# Step 2: Capture real-time traffic with tshark (last 60 sec buffer)
print("[+] Capturing traffic using tshark for protocol analysis and bandwidth...")
proto_summary = defaultdict(int)
bandwidth_total = 0
bandwidth_over_time = defaultdict(int)

try:
    tshark_output = run(f"sudo tshark -i {INTERFACE} -a duration:60 -T fields -e frame.time_epoch -e frame.len -e _ws.col.Protocol")
    for line in tshark_output.splitlines():
        parts = line.strip().split("\t")
        if len(parts) < 3:
            continue
        try:
            timestamp = float(parts[0])
            length = int(parts[1])
            protocol = parts[2] if parts[2] else "Unknown"
            proto_summary[protocol] += length
            bandwidth_total += length
            time_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
            bandwidth_over_time[time_str] += length
        except:
            continue
except Exception as e:
    print(f"[!] Tshark error: {e}")

# Helper: Generate bandwidth graph using plotly
def generate_bandwidth_graph(summary):
    if not summary:
        return "<p>No bandwidth data captured.</p>"

    times, values = zip(*sorted(summary.items()))
    fig = go.Figure(data=[
        go.Scatter(x=list(times), y=list(values), mode='lines+markers', name='Bandwidth (Bytes)', line=dict(color='blue'))
    ])
    fig.update_layout(
        title='Bandwidth Over Time (Bytes)',
        xaxis_title='Time (HH:MM:SS)',
        yaxis_title='Bytes',
        template='plotly_white',
        height=400,
        margin=dict(l=40, r=40, t=40, b=40)
    )
    return fig.to_html(full_html=False)

# Step 3: Generate HTML Report
def generate_table(data_dict):
    if not data_dict:
        return "<p>No data available.</p>"
    rows = "".join([f"<tr><td>{key}</td><td>{val}</td></tr>" for key, val in data_dict.items()])
    return f"<table class='table table-striped'><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>{rows}</tbody></table>"

def generate_html():
    html = f"""
    <html><head>
    <title>📊 Network Usage Summary</title>
    <meta charset='utf-8'>
    <link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css'>
    </head><body class='bg-light'>
    <div class='container mt-4'>
    <h2 class='mb-4'>📡 Internet Monitoring Report</h2>
    <p><b>Time Range:</b> {PAST_TIME} to {NOW}</p>

    <div class='card mb-3'>
        <div class='card-header bg-primary text-white'><strong>Website Browsing Tracking</strong></div>
        <div class='card-body'>{generate_table(squid_summary)}</div>
    </div>

    <div class='card mb-3'>
        <div class='card-header bg-danger text-white'><strong>Content Filtering (DENIED)</strong></div>
        <div class='card-body'>{generate_table(filtered_domains)}</div>
    </div>

    <div class='card mb-3'>
        <div class='card-header bg-info text-white'><strong>Protocol Analysis (Tshark)</strong></div>
        <div class='card-body'>{generate_table(proto_summary)}</div>
    </div>

    <div class='card mb-3'>
        <div class='card-header bg-success text-white'><strong>Bandwidth Consumption</strong></div>
        <div class='card-body'>
            <p>Total Bandwidth Used: {bandwidth_total} Bytes</p>
            {generate_bandwidth_graph(bandwidth_over_time)}
        </div>
    </div>

    <div class='card mb-3'>
        <div class='card-header bg-dark text-white'><strong>User Access Control (Squid ACLs)</strong></div>
        <div class='card-body'><pre>{squid_acl_rules}</pre></div>
    </div>

    <p class='text-muted mt-4'>Generated on {NOW}</p>
    </div></body></html>
    """
    return html

with open(HTML_REPORT, "w") as f:
    f.write(generate_html())

print(f"\n✅ Report generated at: {HTML_REPORT}\n")
