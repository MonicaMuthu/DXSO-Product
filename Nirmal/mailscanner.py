import ipaddress
import subprocess
import platform
import socket
from datetime import datetime

def ping_ip(ip_address):
    """Returns True if the IP address responds to a ping request"""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', str(ip_address)]
    try:
        response = subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return response == 0
    except:
        return False

def check_email_services(ip_address, ports=[25, 465, 587, 993, 995, 110, 143]):
    """Checks if common email ports are open on the IP"""
    email_services = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((str(ip_address), port))
                if result == 0:
                    service_name = {
                        25: "SMTP",
                        465: "SMTPS",
                        587: "SMTP Submission",
                        993: "IMAPS",
                        995: "POP3S",
                        110: "POP3",
                        143: "IMAP"
                    }.get(port, f"Port {port}")
                    email_services.append(service_name)
        except:
            continue
    return email_services

def test_email_flow(ip_address, port):
    """Basic email flow test by attempting to connect and get banner"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((str(ip_address), port))
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner
    except Exception as e:
        return f"Error: {str(e)}"

def scan_network(start_ip, network_range=None):
    """Scans the network and provides email flow report"""
    try:
        start_ip_obj = ipaddress.IPv4Address(start_ip)
    except:
        print(f"Invalid IP address: {start_ip}")
        return
    
    if network_range is None:
        network = ipaddress.IPv4Network(f"{start_ip_obj}/24", strict=False)
    else:
        try:
            network = ipaddress.IPv4Network(f"{start_ip_obj}/{network_range}", strict=False)
        except:
            print("Invalid network range")
            return
    
    print(f"\nScanning network: {network}")
    print(f"Starting scan at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    report = []
    
    for ip in network.hosts():
        if ip >= start_ip_obj:
            if ping_ip(ip):
                print(f"Scanning {ip}...")
                email_services = check_email_services(ip)
                if email_services:
                    ip_report = {
                        'ip': str(ip),
                        'services': [],
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                    
                    for service in email_services:
                        port = {
                            "SMTP": 25,
                            "SMTPS": 465,
                            "SMTP Submission": 587,
                            "IMAPS": 993,
                            "POP3S": 995,
                            "POP3": 110,
                            "IMAP": 143
                        }.get(service)
                        
                        banner = test_email_flow(ip, port)
                        service_report = {
                            'service': service,
                            'port': port,
                            'banner': banner,
                            'status': 'Active' if "Error" not in banner else 'Inactive'
                        }
                        ip_report['services'].append(service_report)
                    
                    report.append(ip_report)
    
    # Generate the final report
    print("\nEmail Flow Monitoring Report")
    print("=" * 50)
    for entry in report:
        print(f"\nIP Address: {entry['ip']}")
        print(f"Scan Time: {entry['timestamp']}")
        print("-" * 50)
        for service in entry['services']:
            print(f"Service: {service['service']} (Port {service['port']})")
            print(f"Status: {service['status']}")
            print(f"Banner: {service['banner']}")
            print("-" * 30)
    
    # Save report to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"email_flow_report_{timestamp}.txt"
    with open(filename, 'w') as f:
        f.write("Email Flow Monitoring Report\n")
        f.write("=" * 50 + "\n")
        for entry in report:
            f.write(f"\nIP Address: {entry['ip']}\n")
            f.write(f"Scan Time: {entry['timestamp']}\n")
            f.write("-" * 50 + "\n")
            for service in entry['services']:
                f.write(f"Service: {service['service']} (Port {service['port']})\n")
                f.write(f"Status: {service['status']}\n")
                f.write(f"Banner: {service['banner']}\n")
                f.write("-" * 30 + "\n")
    
    print(f"\nReport saved to {filename}")

if __name__ == "__main__":
    target_ip = input("Enter the starting IP address to scan: ")
    network_range = input("Enter the network range (e.g., 24 for /24), or press Enter for default: ")
    
    if network_range.strip() == "":
        scan_network(target_ip)
    else:
        scan_network(target_ip, network_range)