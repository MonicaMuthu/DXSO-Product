import subprocess
import os
from datetime import datetime

# ==== CONFIGURATION ====
OUTPUT_DIR = "audit_logs"
os.makedirs(OUTPUT_DIR, exist_ok=True)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = os.path.join(OUTPUT_DIR, f"wifi_audit_{timestamp}.log")


def run_powershell_script(script, args=""):
    full_command = ["powershell.exe", "-Command", script + " " + args]
    try:
        result = subprocess.run(full_command, capture_output=True, text=True)
        with open(log_file, "a") as f:
            f.write(result.stdout + "\n")
            if result.stderr:
                f.write("[!] ERROR:\n" + result.stderr + "\n")
        return result.stdout.strip()
    except Exception as e:
        with open(log_file, "a") as f:
            f.write(f"[!] Exception: {str(e)}\n")
        return f"[!] Exception: {str(e)}"


def main():
    print("\n========== Wi-Fi Security & Traffic Assessment ==========\n")

    # Inputs
    capture_file = input("Enter capture file path (e.g., C:\\pcaps\\file.pcapng): ").strip()
    guest_subnet = input("Enter Guest subnet prefix (default = 192.168.1.): ").strip() or "192.168.1."
    interface_name = input("Enter your Wi-Fi adapter name (e.g., Realtek...): ").strip()

    # Section 1: TLS/Encryption
    print("\n[1] TLS Encryption & Cipher Assessment")
    tls_result = run_powershell_script("""
    param ($CaptureFile)
    function Convert-TLSVersion {
        param($hex)
        switch ($hex.Trim()) {
            "0x0301" { return "TLS 1.0" }
            "0x0302" { return "TLS 1.1" }
            "0x0303" { return "TLS 1.2" }
            "0x0304" { return "TLS 1.3" }
            default { return "Unknown ($hex)" }
        }
    }
    if (!(Test-Path $CaptureFile)) { exit }
    $tlsVersions = tshark -r $CaptureFile -Y "ssl.record.version" -T fields -e ssl.record.version | Sort-Object | Get-Unique
    $output = @()
    if ($tlsVersions) {
        $friendlyVersions = $tlsVersions | ForEach-Object { Convert-TLSVersion $_ }
        $output += "TLS Versions: $($friendlyVersions -join ', ')"
    } else { $output += "No TLS versions found." }
    $cipherSuites = tshark -r $CaptureFile -Y "ssl.handshake.ciphersuite" -T fields -e ssl.handshake.ciphersuite | Sort-Object | Get-Unique
    if ($cipherSuites) {
        $output += "Cipher Suites:`n" + ($cipherSuites -join "`n")
        $weak = $cipherSuites | Where-Object { $_ -match "RC4|3DES|DES|NULL|MD5" }
        if ($weak) {
            $output += "`nWeak Ciphers Found:`n" + ($weak -join "`n")
        } else {
            $output += "No weak ciphers detected."
        }
    } else {
        $output += "No cipher suites found."
    }
    $certs = tshark -r $CaptureFile -Y "ssl.handshake.certificate" -T fields -e x509sat.printableString
    if ($certs) {
        $output += "`nCertificates:`n" + ($certs | Sort-Object | Get-Unique -join "`n")
    } else {
        $output += "No certificates found."
    }
    $output -join "`n"
    """, f"-CaptureFile \"{capture_file}\"")
    print(tls_result)

    # Section 2: Guest Network Traffic
    print("\n[2] Guest & Public IP Discovery")
    guest_result = run_powershell_script("""
    param ($CaptureFile, $GuestSubnetPrefix)
    $ipPairs = tshark -r $CaptureFile -Y "ip" -T fields -e ip.src -e ip.dst
    $guestIPs = @(); $publicIPs = @()
    function IsPrivateIP($ip) {
        return ($ip -like "10.*" -or $ip -like "192.168.*" -or ($ip -like "172.*" -and ([int]($ip.Split('.')[1]) -ge 16 -and [int]($ip.Split('.')[1]) -le 31)))
    }
    foreach ($line in $ipPairs) {
        $parts = $line -split "`t"
        if ($parts.Count -eq 2) {
            $src = $parts[0]; $dst = $parts[1]
            if ($src.StartsWith($GuestSubnetPrefix)) { $guestIPs += $src }
            if ($dst.StartsWith($GuestSubnetPrefix)) { $guestIPs += $dst }
            foreach ($ip in @($src, $dst)) {
                if ($ip -match '^\\d{1,3}(\\.\\d{1,3}){3}$' -and -not (IsPrivateIP $ip)) { $publicIPs += $ip }
            }
        }
    }
    $guestResult = if ($guestIPs) {
        "Guest Devices:`n" + ($guestIPs | Sort-Object -Unique -join "`n")
    } else { "No guest devices found." }
    $publicResult = if ($publicIPs) {
        "`nExternal IPs:`n" + ($publicIPs | Sort-Object -Unique -join "`n")
    } else { "No external IPs found." }
    $guestResult + "`n" + $publicResult
    """, f"-CaptureFile \"{capture_file}\" -GuestSubnetPrefix \"{guest_subnet}\"")
    print(guest_result)

    # Section 3: Firewall
    print("\n[3] Firewall Status")
    firewall_result = run_powershell_script("""
    $profiles = Get-NetFirewallProfile
    $result = @()
    foreach ($p in $profiles) {
        $status = if ($p.Enabled) { "ENABLED" } else { "DISABLED" }
        $result += "$($p.Name) profile: $status"
    }
    if ($result -match "ENABLED") {
        $result += "Firewall is active."
    } else {
        $result += "Warning: Firewall is off."
    }
    $result -join "`n"
    """)
    print(firewall_result)

    # Section 4: Live Traffic Monitoring
    print("\n[4] Real-Time Traffic Monitor")
    traffic_result = run_powershell_script(f"""
    $counterPath = "\\Network Interface({interface_name})\\Bytes Total/sec"
    $sampleInterval = 2
    $maxSamples = 5
    for ($i = 1; $i -le $maxSamples; $i++) {{
        $counter = Get-Counter -Counter $counterPath
        $timestamp = Get-Date -Format "HH:mm:ss"
        $bps = [math]::Round($counter.CounterSamples[0].CookedValue, 2)
        $mbps = [math]::Round(($bps * 8) / 1MB, 4)
        Write-Host "$timestamp`t$bps B/s`t$mbps Mbps"
        Start-Sleep -Seconds $sampleInterval
    }}
    """)
    print(traffic_result)

    # Section 5: Auth Check
    print("\n[5] Recent Logins")
    login_result = run_powershell_script("""
    Get-CimInstance Win32_LogonSession |
    Select-Object LogonId, LogonType, AuthenticationPackage, StartTime |
    Sort-Object StartTime | Format-Table -AutoSize
    """)
    print(login_result)

    print(f"\n[✓] All tasks completed. Log saved at: {log_file}\n")


if __name__ == "__main__":
    main()
