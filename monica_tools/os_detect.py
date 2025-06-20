import platform
import subprocess
import requests
import datetime

# OS EOL dates - expand this based on your inventory
OS_EOL_DATES = {
    "Windows 10": "2025-10-14",
    "Windows 11": "2031-10-14",
    "Ubuntu 20.04": "2025-04-30",
    "Ubuntu 22.04": "2027-04-30",
    "Kali Linux": "2025-12-01"
}

def get_os_info():
    system = platform.system()
    release = platform.release()
    version = platform.version()
    os_full = f"{system} {release}"
    
    print(f"\n[OS IDENTIFICATION]")
    print(f"Operating System: {os_full}")
    print(f"Kernel Version : {version}")
    return os_full

def get_installed_packages():
    print(f"\n[PATCH LEVEL ASSESSMENT]")
    try:
        if platform.system() == "Windows":
            print("[!] Windows patch list via WMIC (limited info).")
            output = subprocess.check_output("wmic qfe list brief", shell=True)
            patches = output.decode(errors='ignore').splitlines()
        elif platform.system() == "Linux":
            output = subprocess.check_output("dpkg -l", shell=True)
            patches = output.decode(errors='ignore').splitlines()
        else:
            print("[!] Unsupported OS for patch check.")
            return []

        top_installed = patches[:10]  # Trim to reduce API load
        for patch in top_installed:
            print("  →", patch[:80])
        return top_installed
    except Exception as e:
        print(f"[X] Could not fetch installed software: {str(e)}")
        return []

def check_vulnerabilities(software_list):
    print(f"\n[VULNERABILITY DETECTION VIA VULNERS API]")
    headers = {'User-Agent': 'Mozilla/5.0'}
    base_url = "https://vulners.com/api/v3/search/lucene/"
    
    for entry in software_list:
        if not entry.strip():
            continue  # Skip empty lines

        try:
            words = entry.split()
            if len(words) < 1 or words[0].lower() in ['description', 'name']:
                continue  # Skip headers or malformed lines

            query = words[0]

            response = requests.get(f"{base_url}?query={query}", headers=headers, timeout=10)
            data = response.json()

            if data.get('result') == 'OK' and data['data'].get('documents'):
                print(f"\n[!] Potential Vulns for: {query}")
                for vuln in data['data']['documents'][:3]:
                    print(f"  - {vuln['id']}: {vuln['title']}")
            else:
                print(f"[-] No major vulnerabilities found for: {query}")
        except Exception as e:
            print(f"[ERROR] Vulners query failed for {query}: {str(e)}")


def check_os_lifecycle(os_name):
    print(f"\n[OS LIFECYCLE MANAGEMENT CHECK]")
    for name in OS_EOL_DATES:
        if name.lower() in os_name.lower():
            eol_date = datetime.datetime.strptime(OS_EOL_DATES[name], "%Y-%m-%d")
            days_left = (eol_date - datetime.datetime.now()).days
            if days_left < 0:
                print(f"[X] {name} is End-of-Life since {eol_date.date()}")
            else:
                print(f"[✓] {name} is supported. {days_left} days left until EOL.")
            return
    print("[?] OS not found in EOL DB. Add to OS_EOL_DATES for tracking.")

if __name__ == "__main__":
    print("=== Local Device OS Audit ===")
    os_name = get_os_info()
    patch_list = get_installed_packages()
    check_vulnerabilities(patch_list)
    check_os_lifecycle(os_name)
