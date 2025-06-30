import os
import json
import subprocess
import requests
from datetime import datetime
from requests.auth import HTTPBasicAuth
from concurrent.futures import ThreadPoolExecutor

# Configuration
OPENNMS_BASE_URL = "http://localhost:8980/opennms/rest"
AUTH = HTTPBasicAuth("admin", "admin")
HEADERS = {"Accept": "application/json"}
REPORT_DIR = "./opennms_reports"
os.makedirs(REPORT_DIR, exist_ok=True)
JSON_REPORT = os.path.join(REPORT_DIR, "report_latest.json")
HTML_REPORT = os.path.join(REPORT_DIR, "report_latest.html")

# === Helper: Format Timestamp ===
def format_time(ts):
    try:
        timestamp = int(str(ts)[:13])
        return datetime.fromtimestamp(timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return "Invalid"

# === OpenNMS Fetch ===
def fetch_opennms_data():
    try:
        nodes = requests.get(f"{OPENNMS_BASE_URL}/nodes", auth=AUTH, headers=HEADERS).json().get("node", [])
        alarms = requests.get(f"{OPENNMS_BASE_URL}/alarms", auth=AUTH, headers=HEADERS).json().get("alarm", [])
        outages = requests.get(f"{OPENNMS_BASE_URL}/outages", auth=AUTH, headers=HEADERS).json().get("outage", [])
        return {"nodes": nodes, "alarms": alarms, "outages": outages}
    except Exception as e:
        print(f"[ERROR] OpenNMS fetch failed: {e}")
        return {"nodes": [], "alarms": [], "outages": []}

# === ARP Scan Device Discovery ===
def discover_devices():
    try:
        output = subprocess.check_output("sudo arp-scan -l", shell=True, text=True)
        devices = []
        for line in output.splitlines()[2:-2]:
            parts = line.split("\t")
            if len(parts) >= 2:
                devices.append({"ip": parts[0], "mac": parts[1]})
        return devices
    except subprocess.CalledProcessError:
        return []

# === Firmware Info via SSH ===
def get_firmware(ip):
    try:
        out = subprocess.check_output(
            f"ssh -o ConnectTimeout=3 {ip} 'uname -a'",
            shell=True,
            stderr=subprocess.DEVNULL
        ).decode().strip()
        return out
    except subprocess.CalledProcessError:
        return "Unavailable"

def fetch_firmwares(nodes):
    ips = [n.get("label") for n in nodes if n.get("label")]
    firmware = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(lambda ip: (ip, get_firmware(ip)), ips)
    for ip, fw in results:
        firmware[ip] = fw
    return firmware

# === Topology & Dependency ===
def infer_links(nodes):
    labels = [n.get("label", "") for n in nodes]
    return [(labels[i], labels[i + 1]) for i in range(len(labels) - 1)]

def analyze_dependencies(nodes):
    return [{"device": n.get("label", ""), "depends_on": "192.168.1.1"} for n in nodes if n.get("label", "").startswith("192.168.1.")]

def detect_unauthorized(discovered, known):
    known_ips = {n.get("label") for n in known}
    return [d for d in discovered if d["ip"] not in known_ips]

# === HTML Report ===
def generate_html(data):
    total_nodes = len(data['nodes'])
    total_unauth = len(data['unauthorized'])
    total_links = len(data['links'])
    total_deps = len(data['dependencies'])
    total_fw_unavailable = sum(1 for fw in data['firmware'].values() if fw == "Unavailable")
    total_alarms = len(data['alarms'])
    total_outages = len(data['outages'])

    def tablerows(rows): return "".join(rows)
    return f"""<!DOCTYPE html>
<html><head><meta charset='UTF-8'><title>Network Device Management</title>
<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'>
<style>
.card-summary {{ background-color: #f8f9fa; border-left: 5px solid #007bff; padding: 15px; margin-bottom: 20px; }}
.table thead th {{ background-color: #e9ecef; }}
</style></head><body class='bg-light'>
<div class='container my-4'>
<h2 class='text-center mb-4'>📡 Organizational Network Device Assessment Report</h2>
<p><strong>Generated on:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<div class='row'>
  <div class='col-md-4'><div class='card-summary'><strong>Total Devices:</strong> {total_nodes}</div></div>
  <div class='col-md-4'><div class='card-summary'><strong>Unauthorized Devices:</strong> {total_unauth}</div></div>
  <div class='col-md-4'><div class='card-summary'><strong>Active Alarms:</strong> {total_alarms}</div></div>
</div>

<h4>📍 Discovered Devices</h4>
<p class='text-muted'>Total: {total_nodes}</p>
<table class='table table-bordered table-sm'><thead><tr><th>ID</th><th>Label</th><th>Created</th></tr></thead><tbody>
{tablerows([f"<tr><td>{n['id']}</td><td>{n.get('label', '')}</td><td>{format_time(n.get('createTime'))}</td></tr>" for n in data['nodes']])}
</tbody></table>

<h4>🚫 Unauthorized Devices</h4>
<p class='text-muted'>Devices found in scan but not in OpenNMS: {total_unauth}</p>
<table class='table table-bordered table-sm'><thead><tr><th>IP</th><th>MAC</th></tr></thead><tbody>
{tablerows([f"<tr><td>{d['ip']}</td><td>{d['mac']}</td></tr>" for d in data['unauthorized']])}
</tbody></table>

<h4>🗺️ Device Mapping</h4>
<p class='text-muted'>Inferred links between discovered devices</p>
<table class='table table-bordered table-sm'><thead><tr><th>From</th><th>To</th></tr></thead><tbody>
{tablerows([f"<tr><td>{l[0]}</td><td>{l[1]}</td></tr>" for l in data['links']])}
</tbody></table>

<h4>🔗 Dependencies</h4>
<p class='text-muted'>Auto-detected device relationships</p>
<table class='table table-bordered table-sm'><thead><tr><th>Device</th><th>Depends On</th></tr></thead><tbody>
{tablerows([f"<tr><td>{d['device']}</td><td>{d['depends_on']}</td></tr>" for d in data['dependencies']])}
</tbody></table>

<h4>⚙️ Firmware Info</h4>
<p class='text-muted'>Unavailable: {total_fw_unavailable}</p>
<table class='table table-bordered table-sm'><thead><tr><th>Device</th><th>Firmware</th></tr></thead><tbody>
{tablerows([f"<tr><td>{ip}</td><td>{fw}</td></tr>" for ip, fw in data['firmware'].items()])}
</tbody></table>

<h4>🚨 Alarms</h4>
<table class='table table-bordered table-sm'><thead><tr><th>ID</th><th>Description</th><th>Severity</th><th>Log</th></tr></thead><tbody>
{tablerows([f"<tr><td>{a['id']}</td><td>{a.get('description', '')}</td><td>{a.get('severity', '')}</td><td>{a.get('logMessage', '')}</td></tr>" for a in data['alarms']])}
</tbody></table>

<h4>📉 Outages</h4>
<table class='table table-bordered table-sm'><thead><tr><th>ID</th><th>Service</th><th>IP</th><th>Time</th></tr></thead><tbody>
{tablerows([
    f"<tr><td>{o.get('id')}</td>"
    f"<td>{o.get('serviceType', {}).get('name', 'N/A')}</td>"
    f"<td>{o.get('ipAddress', 'N/A')}</td>"
    f"<td>{format_time(o.get('lostService')) if o.get('lostService') else 'N/A'}</td></tr>"
    for o in data['outages']
])}
</tbody></table>

<p class='text-muted small mt-4'>Generated as part of SIEM/SOAR readiness posture script</p>
</div></body></html>"""

# === Main Entry ===
if __name__ == "__main__":
    print("🔄 Collecting network posture data...")
    report = fetch_opennms_data()
    discovered = discover_devices()
    report["unauthorized"] = detect_unauthorized(discovered, report["nodes"])
    report["links"] = infer_links(report["nodes"])
    report["dependencies"] = analyze_dependencies(report["nodes"])
    report["firmware"] = fetch_firmwares(report["nodes"])

    with open(JSON_REPORT, "w") as f:
        json.dump(report, f, indent=2)

    with open(HTML_REPORT, "w") as f:
        f.write(generate_html(report))

    print(f"✅ Report generated:\n- JSON: {JSON_REPORT}\n- HTML: {HTML_REPORT}")
