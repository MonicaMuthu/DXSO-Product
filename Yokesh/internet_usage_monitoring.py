import subprocess, json, os
from datetime import datetime

# File paths
log_dir = "/var/log/internet_monitoring"
os.makedirs(log_dir, exist_ok=True)
report_file_json = os.path.join(log_dir, "report_latest.json")
report_file_html = os.path.join(log_dir, "report_latest.html")

# Command runner
def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True).strip()
    except subprocess.CalledProcessError as e:
        return f"[ERROR] {e}"

# Parse vnstat bandwidth data
def parse_vnstat_bandwidth():
    raw = run("vnstat --json")
    try:
        data = json.loads(raw)
        days = data['interfaces'][0]['traffic']['days']
        return [{"date": f"{d['date']['year']}-{d['date']['month']:02d}-{d['date']['day']:02d}",
                 "rx": d['rx'], "tx": d['tx']} for d in days]
    except Exception as e:
        return f"[ERROR] {e}"

# Organize user access control entries
def format_user_access_control():
    raw = run("grep -E '^(acl|http_access)' /etc/squid/squid.conf")
    lines = raw.splitlines()
    organized = "\n".join(sorted(lines))
    return organized

# Generate monitoring data
report = {
    "timestamp": datetime.now().isoformat(),
    "website_browsing": run("tail -n 100 /var/log/squid/access.log | awk '{print $3, $7}'"),
    "usage_time": run("curl -s http://127.0.0.1:3000/lua/rest/v1/get/host_traffic.lua | head -n 30"),
    "content_filtering": run("grep DENIED /var/log/squid/access.log | tail -n 30"),
    "bandwidth": parse_vnstat_bandwidth(),
    "protocols": run("tshark -i eth0 -a duration:10 -q -z io,phs"),
    "anomalies": run("curl -s http://127.0.0.1:3000/lua/rest/v1/get/alerts"),
    "realtime_usage": run("iftop -t -s 10 | head -n 20"),
    "usage_summary": run("vnstat -d"),
    "user_access_control": format_user_access_control()
}

# Save JSON
with open(report_file_json, "w") as f:
    json.dump(report, f, indent=4)

# HTML template with Chart.js
def generate_html(report):
    def section(title, content):
        return f"""
        <div class="card mb-4">
            <div class="card-header bg-dark text-white"><strong>{title}</strong></div>
            <div class="card-body"><pre><code>{content}</code></pre></div>
        </div>
        """

    # Bandwidth labels and values for Chart.js
    labels = [d["date"] for d in report["bandwidth"] if isinstance(d, dict)]
    rx = [round(d["rx"] / 1024, 2) for d in report["bandwidth"] if isinstance(d, dict)]
    tx = [round(d["tx"] / 1024, 2) for d in report["bandwidth"] if isinstance(d, dict)]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Internet Monitoring Report</title>
    <meta http-equiv="refresh" content="60">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light text-dark">
<div class="container my-4">
    <h1 class="text-center mb-4">📊 Internet Usage Monitoring Report</h1>
    <p><strong>Generated:</strong> {report['timestamp']}</p>
    
    {section("Website Browsing", report['website_browsing'])}
    {section("Usage Time (Per Host)", report['usage_time'])}
    {section("Content Filtering (DENIED logs)", report['content_filtering'])}

    <div class="card mb-4">
        <div class="card-header bg-dark text-white"><strong>Bandwidth Consumption (vnstat)</strong></div>
        <div class="card-body">
            <canvas id="bandwidthChart" height="100"></canvas>
        </div>
    </div>

    {section("Protocol Analysis (tshark)", report['protocols'])}
    {section("Anomaly Detection (ntopng alerts)", report['anomalies'])}
    {section("Real-Time Usage (iftop)", report['realtime_usage'])}
    {section("Usage Summary (vnstat -d)", report['usage_summary'])}
    {section("User Access Control (Squid ACLs)", report['user_access_control'])}

    <p class="text-muted small mt-5">Auto-refreshes every 60 seconds. File: <code>report_latest.html</code></p>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
const ctx = document.getElementById('bandwidthChart').getContext('2d');
const chart = new Chart(ctx, {{
    type: 'bar',
    data: {{
        labels: {json.dumps(labels)},
        datasets: [
            {{
                label: 'Download (MB)',
                data: {json.dumps(rx)},
                backgroundColor: 'rgba(54, 162, 235, 0.7)'
            }},
            {{
                label: 'Upload (MB)',
                data: {json.dumps(tx)},
                backgroundColor: 'rgba(255, 99, 132, 0.7)'
            }}
        ]
    }},
    options: {{
        responsive: true,
        plugins: {{
            legend: {{ position: 'top' }},
            title: {{ display: true, text: 'Daily Bandwidth Usage' }}
        }},
        scales: {{
            y: {{
                beginAtZero: true,
                title: {{ display: true, text: 'MB' }}
            }}
        }}
    }}
}});
</script>
</body>
</html>
"""
    return html

# Write HTML
with open(report_file_html, "w") as f:
    f.write(generate_html(report))

print(f"✅ Monitoring JSON saved to: {report_file_json}")
print(f"✅ HTML report saved to: {report_file_html}")

