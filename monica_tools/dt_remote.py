import winrm
import os

# === CONFIG ===
REMOTE_HOST = '192.168.1.15'  # Change to remote IP or hostname
USERNAME = 'AdminUser'        # Admin user on remote PC
PASSWORD = 'YourStrongPassword'
AGENT_NAME = 'monitor_agent.exe'
REMOTE_PATH = f'C:\\Windows\\Temp\\{AGENT_NAME}'

# === STEP 1: Upload File ===
def upload_file():
    print("[*] Uploading agent via PowerShell...")
    encoded = ""
    with open(AGENT_NAME, 'rb') as f:
        encoded = f.read().hex()

    # Create hex string -> file on remote
    hex_script = f"""
    $hex = "{encoded}"
    $bytes = for ($i=0; $i -lt $hex.Length; $i+=2) {{
        [Convert]::ToByte($hex.Substring($i,2),16)
    }}
    [IO.File]::WriteAllBytes("{REMOTE_PATH}", $bytes)
    """

    session = winrm.Session(f'http://{REMOTE_HOST}:5985/wsman', auth=(USERNAME, PASSWORD))
    result = session.run_ps(hex_script)
    if result.status_code == 0:
        print("[+] Upload successful.")
    else:
        print("[-] Upload failed:", result.std_err.decode())

# === STEP 2: Execute File ===
def run_remote_agent():
    print("[*] Running agent on remote machine...")
    session = winrm.Session(f'http://{REMOTE_HOST}:5985/wsman', auth=(USERNAME, PASSWORD))
    result = session.run_cmd(f'powershell -Command "Start-Process \'{REMOTE_PATH}\'"')
    if result.status_code == 0:
        print("[+] Agent started successfully.")
    else:
        print("[-] Execution failed:", result.std_err.decode())

# === MAIN ===
if __name__ == "__main__":
    upload_file()
    run_remote_agent()
