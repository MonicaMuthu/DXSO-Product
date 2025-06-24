import os, json, subprocess
from datetime import datetime

report = {
    "timestamp": datetime.now().isoformat(),
    "authentication_mechanisms": [],
    "login_attempts": {"success": [], "failed": []},
    "remote_access_audit": [],
    "user_privileges": [],
    "mfa_status": "Not Checked"
}

# 1. Authentication Mechanisms Detection
def detect_auth_methods():
    methods = []
    sshd_config = "/etc/ssh/sshd_config"
    if os.path.exists(sshd_config):
        with open(sshd_config, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("PasswordAuthentication") or line.startswith("PubkeyAuthentication"):
                    methods.append(line)
    return methods

# 2. Login Monitoring via journalctl
def analyze_auth_log():
    try:
        result = subprocess.check_output(
            "journalctl _COMM=sshd --since '2 days ago' --no-pager", 
            shell=True, text=True
        )
        for line in result.splitlines():
            if "Failed password" in line:
                report["login_attempts"]["failed"].append(line.strip())
            elif "Accepted password" in line or "Accepted publickey" in line:
                report["login_attempts"]["success"].append(line.strip())
            if "sshd" in line and ("Accepted" in line or "Failed" in line):
                report["remote_access_audit"].append(line.strip())
    except Exception as e:
        print("❌ Error reading journalctl logs:", e)

# 3. User Privileges Review
def review_privileges():
    users = []
    with open("/etc/passwd", "r") as f:
        for line in f:
            parts = line.strip().split(":")
            username, uid = parts[0], int(parts[2])
            if uid >= 1000 and username not in ['nobody']:
                is_sudo = os.system(f"groups {username} | grep -q sudo") == 0
                users.append({"user": username, "is_sudo": is_sudo})
    report["user_privileges"] = users

# 4. MFA Check via Keycloak Config
def check_keycloak_mfa():
    try:
        kc_config_path = "/opt/keycloak/standalone/configuration/standalone.xml"
        if os.path.exists(kc_config_path):
            with open(kc_config_path, "r") as f:
                content = f.read()
                if "otpPolicy" in content or "totp" in content:
                    report["mfa_status"] = "MFA Configured"
                else:
                    report["mfa_status"] = "MFA Not Configured"
        else:
            report["mfa_status"] = "Keycloak config not found"
    except Exception as e:
        report["mfa_status"] = f"MFA check failed: {str(e)}"

# 5. Save report in same directory with improved HTML
def save_reports():
    current_dir = os.getcwd()
    json_path = os.path.join(current_dir, "access_control_report.json")
    html_path = os.path.join(current_dir, "access_control_report.html")

    with open(json_path, "w") as f:
        json.dump(report, f, indent=4)

    html_content = f"""
    <html>
    <head>
        <title>Access Control Analysis Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #f8f9fa;
                padding: 20px;
                color: #333;
            }}
            h1, h2 {{
                color: #2c3e50;
            }}
            h2 {{
                margin-top: 30px;
                border-bottom: 2px solid #ccc;
                padding-bottom: 5px;
            }}
            ul {{
                background-color: #fff;
                padding: 10px 20px;
                border-radius: 8px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.05);
                list-style: disc inside;
            }}
            li {{
                padding: 4px 0;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
            }}
            th, td {{
                border: 1px solid #ccc;
                padding: 8px;
                text-align: left;
            }}
            th {{
                background-color: #e8e8e8;
            }}
            .box {{
                background-color: #fff;
                padding: 15px;
                border-radius: 8px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.05);
                margin-top: 10px;
            }}
        </style>
    </head>
    <body>
        <h1>Access Control Analysis Report</h1>
        <p><strong>Generated On:</strong> {report['timestamp']}</p>

        <h2>Authentication Mechanisms</h2>
        <div class="box">
            <ul>
                {''.join(f'<li>{line}</li>' for line in report['authentication_mechanisms']) or '<li>No authentication settings found.</li>'}
            </ul>
        </div>

        <h2>Login Attempts</h2>
        <h3>Successful</h3>
        <div class="box">
            <ul>
                {''.join(f'<li>{entry}</li>' for entry in report['login_attempts']['success']) or '<li>No successful login attempts.</li>'}
            </ul>
        </div>

        <h3>Failed</h3>
        <div class="box">
            <ul>
                {''.join(f'<li>{entry}</li>' for entry in report['login_attempts']['failed']) or '<li>No failed login attempts.</li>'}
            </ul>
        </div>

        <h2>Remote Access Audit</h2>
        <div class="box">
            <ul>
                {''.join(f'<li>{entry}</li>' for entry in report['remote_access_audit']) or '<li>No remote access detected.</li>'}
            </ul>
        </div>

        <h2>User Privileges</h2>
        <div class="box">
            <table>
                <tr><th>User</th><th>Sudo Access</th></tr>
                {''.join(f'<tr><td>{user["user"]}</td><td>{"Yes" if user["is_sudo"] else "No"}</td></tr>' for user in report['user_privileges'])}
            </table>
        </div>

        <h2>MFA Status</h2>
        <div class="box">
            <p>{report['mfa_status']}</p>
        </div>
    </body>
    </html>
    """

    with open(html_path, "w") as f:
        f.write(html_content)

    print(f"✅ Reports saved:\n- JSON: {json_path}\n- HTML: {html_path}")

# Run everything
if __name__ == "__main__":
    print("🔍 Running Access Control Analysis...")
    report["authentication_mechanisms"] = detect_auth_methods()
    analyze_auth_log()
    review_privileges()
    check_keycloak_mfa()
    save_reports()
    print("✅ Access Control Analysis Completed.")

