import os
import json
import requests
import subprocess
from datetime import datetime
from requests.auth import HTTPBasicAuth

# File paths
report_dir = "./opennms_reports"
os.makedirs(report_dir, exist_ok=True)
report_json = os.path.join(report_dir, "report_latest.json")
report_html = os.path.join(report_dir, "report_latest.html")

# Fetch OpenNMS data
def fetch_opennms_data():
    base_url = "http://localhost:8980/opennms/rest"
    auth = HTTPBasicAuth("admin", "admin")

    try:
        headers = {"Accept": "application/json"}

        # Get nodes
        nodes_resp = requests.get(f"{base_url}/nodes", auth=auth, headers=headers)
        nodes_resp.raise_for_status()
        nodes = nodes_resp.json().get("node", [])

        # Get alarms
        alarms_resp = requests.get(f"{base_url}/alarms", auth=auth, headers=headers)
        alarms_resp.raise_for_status()
        alarms = alarms_resp.json().get("alarm", [])

        # Get outages
        outages_resp = requests.get(f"{base_url}/outages", auth=auth, headers=headers)
        outages_resp.raise_for_status()
        outages = outages_resp.json().get("outage", [])

        return {
            "nodes": nodes,
            "alarms": alarms,
            "outages": outages
        }

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch OpenNMS data: {e}")
        return {"nodes": [], "alarms": [], "outages": []}

# Simulate device mapping

def infer_device_links(nodes):
    links = []
    ip_list = [node['label'] for node in nodes if 'label' in node]
    for i in range(len(ip_list) - 1):
        links.append((ip_list[i], ip_list[i + 1]))
    return links

# Simulate device dependencies

def analyze_dependencies(nodes):
    dependencies = []
    for node in nodes:
        ip = node['label']
        if ip.startswith("192.168.1."):
            dependencies.append({"device": ip, "depends_on": "192.168.1.1"})
    return dependencies

# Fetch firmware version via SSH

def get_firmware_version(ip):
    try:
        output = subprocess.check_output(
            f"ssh -o ConnectTimeout=3 {ip} 'uname -a'",
            shell=True,
            stderr=subprocess.DEVNULL
        ).decode().strip()
        return output
    except subprocess.CalledProcessError:
        return "Unavailable"

# Save JSON
report = fetch_opennms_data()
report["links"] = infer_device_links(report["nodes"])
report["dependencies"] = analyze_dependencies(report["nodes"])
report["firmware"] = {node['label']: get_firmware_version(node['label']) for node in report["nodes"]}

with open(report_json, "w") as f:
    json.dump(report, f, indent=4)

# Generate HTML
html = f"""<!DOCTYPE html>
<html lang='en'>
<head>
  <meta charset='UTF-8'>
  <title>OpenNMS Report</title>
  <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'>
</head>
<body class='bg-light'>
  <div class='container my-4'>
    <h2 class='text-center mb-4'>📡 Network Device Monitoring Report</h2>
    <p><strong>Generated:</strong> {datetime.now().isoformat()}</p>

    <h4 class='mt-4'>Discovered Nodes</h4>
    <table class='table table-bordered table-sm'>
      <thead><tr><th>ID</th><th>Name</th><th>Create Time</th></tr></thead>
      <tbody>
        {''.join([f"<tr><td>{n['id']}</td><td>{n.get('label', 'Unknown')}</td><td>{n.get('createTime', '')}</td></tr>" for n in report['nodes']])}
      </tbody>
    </table>

    <h4 class='mt-4'>Device Mapping (Simulated)</h4>
    <table class='table table-bordered table-sm'>
      <thead><tr><th>From</th><th>To</th></tr></thead>
      <tbody>
        {''.join([f"<tr><td>{link[0]}</td><td>{link[1]}</td></tr>" for link in report['links']])}
      </tbody>
    </table>

    <h4 class='mt-4'>Device Dependencies (Simulated)</h4>
    <table class='table table-bordered table-sm'>
      <thead><tr><th>Device</th><th>Depends On</th></tr></thead>
      <tbody>
        {''.join([f"<tr><td>{d['device']}</td><td>{d['depends_on']}</td></tr>" for d in report['dependencies']])}
      </tbody>
    </table>

    <h4 class='mt-4'>Firmware Info (SSH)</h4>
    <table class='table table-bordered table-sm'>
      <thead><tr><th>Device</th><th>Firmware</th></tr></thead>
      <tbody>
        {''.join([f"<tr><td>{ip}</td><td>{ver}</td></tr>" for ip, ver in report['firmware'].items()])}
      </tbody>
    </table>

    <h4 class='mt-4'>Current Alarms</h4>
    <table class='table table-bordered table-sm'>
      <thead><tr><th>ID</th><th>Description</th><th>Severity</th><th>Log Message</th></tr></thead>
      <tbody>
        {''.join([f"<tr><td>{a['id']}</td><td>{a.get('description', '')}</td><td>{a.get('severity', '')}</td><td>{a.get('logMessage', '')}</td></tr>" for a in report['alarms']])}
      </tbody>
    </table>

    <h4 class='mt-4'>Current Outages</h4>
    <table class='table table-bordered table-sm'>
      <thead><tr><th>ID</th><th>Service</th><th>IP Address</th><th>Lost Service Time</th></tr></thead>
      <tbody>
        {''.join([f"<tr><td>{o['id']}</td><td>{o.get('serviceType', {}).get('name', '')}</td><td>{o.get('ipAddress', '')}</td><td>{o.get('lostService', '')}</td></tr>" for o in report['outages']])}
      </tbody>
    </table>

    <p class='text-muted small mt-4'>Auto-generated from OpenNMS Docker setup</p>
  </div>
</body>
</html>"""

# Save HTML
with open(report_html, "w") as f:
    f.write(html)

print(f"✅ Report generated successfully:\nHTML: {report_html}\nJSON: {report_json}")

