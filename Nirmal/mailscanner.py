#!/usr/bin/env python3
import socket
import smtplib
import imaplib
import poplib
import ssl
from datetime import datetime
import json
import time
from collections import defaultdict
import threading
import argparse
from scapy.all import sniff, IP, TCP, Raw
import logging
import csv
import matplotlib.pyplot as plt
import pandas as pd

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('email_monitor.log'),
        logging.StreamHandler()
    ]
)

class EmailTrafficMonitor:
    def __init__(self):
        self.traffic_stats = defaultdict(lambda: defaultdict(int))
        self.alerts = []
        self.email_ports = [25, 465, 587, 993, 995, 110, 143]
        self.running = False
        self.start_time = datetime.now()
        self.setup_alert_rules()

    def setup_alert_rules(self):
        self.alert_rules = {
            'high_volume': {
                'threshold': 100,  # emails per minute
                'message': "High email volume detected from {} to {}:{} - {} emails"
            },
            'unencrypted_auth': {
                'message': "Unencrypted authentication attempt detected from {} to {}:{}"
            },
            'suspicious_command': {
                'keywords': ['VRFY', 'EXPN', 'PASS', 'LOGIN'],
                'message': "Suspicious command detected from {} to {}:{} - {}"
            }
        }

    def start_live_capture(self, interface, duration=0):
        """Start live packet capture on specified interface"""
        self.running = True
        logging.info(f"Starting live email traffic capture on interface {interface}")
        
        # Start packet capture in separate thread
        capture_thread = threading.Thread(
            target=self._capture_traffic,
            args=(interface, duration)
        )
        capture_thread.start()

        # Start alert monitoring in separate thread
        alert_thread = threading.Thread(target=self._monitor_alerts)
        alert_thread.start()

        return capture_thread, alert_thread

    def _capture_traffic(self, interface, duration):
        """Internal method for packet capture"""
        try:
            sniff(
                iface=interface,
                prn=self._packet_callback,
                filter=f"tcp port {' or tcp port '.join(map(str, self.email_ports))}",
                timeout=duration
            )
        except Exception as e:
            logging.error(f"Packet capture error: {e}")
        finally:
            self.running = False
            logging.info("Packet capture completed")

    def _packet_callback(self, packet):
        """Process each captured packet"""
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            
            if dst_port in self.email_ports:
                # Update traffic statistics
                key = (src_ip, dst_ip, dst_port)
                self.traffic_stats[key]['bytes'] += len(packet)
                self.traffic_stats[key]['packets'] += 1
                self.traffic_stats[key]['last_activity'] = datetime.now().isoformat()

                # Analyze packet content
                if packet.haslayer(Raw):
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        self._analyze_payload(src_ip, dst_ip, dst_port, payload)
                    except Exception as e:
                        logging.debug(f"Payload analysis error: {e}")

    def _analyze_payload(self, src_ip, dst_ip, port, payload):
        """Analyze email protocol payload for suspicious activity"""
        # Check for suspicious commands
        for cmd in self.alert_rules['suspicious_command']['keywords']:
            if cmd in payload.upper():
                alert_msg = self.alert_rules['suspicious_command']['message'].format(
                    src_ip, dst_ip, port, cmd
                )
                self._trigger_alert(alert_msg, 'suspicious_command')

        # Check for unencrypted authentication on non-SSL ports
        if port in [25, 110, 143] and ('PASS ' in payload or 'LOGIN ' in payload):
            alert_msg = self.alert_rules['unencrypted_auth']['message'].format(
                src_ip, dst_ip, port
            )
            self._trigger_alert(alert_msg, 'unencrypted_auth')

    def _monitor_alerts(self):
        """Monitor traffic for alert conditions"""
        while self.running:
            time.sleep(60)  # Check every minute
            
            # Check for high volume
            for (src, dst, port), stats in self.traffic_stats.items():
                if stats['packets'] > self.alert_rules['high_volume']['threshold']:
                    alert_msg = self.alert_rules['high_volume']['message'].format(
                        src, dst, port, stats['packets']
                    )
                    self._trigger_alert(alert_msg, 'high_volume')
                    stats['packets'] = 0  # Reset counter

    def _trigger_alert(self, message, alert_type):
        """Record and log an alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'message': message
        }
        self.alerts.append(alert)
        logging.warning(f"ALERT: {message}")

    def test_email_services(self, ip_address):
        """Test email services on a specific IP"""
        results = {
            'ip': ip_address,
            'timestamp': datetime.now().isoformat(),
            'services': []
        }
        
        for port in self.email_ports:
            service = self._identify_service(port)
            if self._is_port_open(ip_address, port):
                service_result = {
                    'port': port,
                    'service': service,
                    'status': 'open',
                    'details': self._test_service(ip_address, port, service)
                }
                results['services'].append(service_result)
        
        return results

    def _identify_service(self, port):
        """Identify service by port number"""
        services = {
            25: "SMTP",
            465: "SMTPS",
            587: "SMTP Submission",
            993: "IMAPS",
            995: "POP3S",
            110: "POP3",
            143: "IMAP"
        }
        return services.get(port, f"Unknown ({port})")

    def _is_port_open(self, ip, port, timeout=2):
        """Check if a port is open"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((ip, port)) == 0
        except:
            return False

    def _test_service(self, ip, port, service):
        """Test specific email service"""
        try:
            if 'SMTP' in service:
                return self._test_smtp(ip, port)
            elif 'IMAP' in service:
                return self._test_imap(ip, port)
            elif 'POP' in service:
                return self._test_pop3(ip, port)
            else:
                return {'banner': self._get_banner(ip, port)}
        except Exception as e:
            return {'error': str(e)}

    def _test_smtp(self, ip, port):
        """Test SMTP service"""
        result = {}
        try:
            if port in [465, 587]:
                context = ssl.create_default_context()
                if port == 465:
                    with smtplib.SMTP_SSL(ip, port, timeout=5, context=context) as server:
                        result['banner'] = server.ehlo()[1]
                else:  # port 587
                    with smtplib.SMTP(ip, port, timeout=5) as server:
                        result['banner'] = server.ehlo()[1]
                        result['starttls'] = server.has_extn('STARTTLS')
                        if result['starttls']:
                            server.starttls(context=context)
                            result['ehlo_response'] = server.ehlo()[1]
            else:  # port 25
                with smtplib.SMTP(ip, port, timeout=5) as server:
                    result['banner'] = server.ehlo()[1]
                    result['starttls'] = server.has_extn('STARTTLS')
                    if result['starttls']:
                        context = ssl.create_default_context()
                        server.starttls(context=context)
                        result['ehlo_response'] = server.ehlo()[1]
        except Exception as e:
            result['error'] = str(e)
        return result

    def _test_imap(self, ip, port):
        """Test IMAP service"""
        result = {}
        try:
            if port == 993:  # IMAPS
                context = ssl.create_default_context()
                with imaplib.IMAP4_SSL(ip, port, timeout=5, ssl_context=context) as imap:
                    result['banner'] = imap.welcome.decode('utf-8', errors='ignore')
                    typ, data = imap.capability()
                    if typ == 'OK':
                        result['capabilities'] = data[0].decode('utf-8', errors='ignore').split()
            else:  # IMAP (143)
                with imaplib.IMAP4(ip, port, timeout=5) as imap:
                    result['banner'] = imap.welcome.decode('utf-8', errors='ignore')
                    typ, data = imap.capability()
                    if typ == 'OK':
                        result['capabilities'] = data[0].decode('utf-8', errors='ignore').split()
                        result['starttls'] = 'STARTTLS' in result['capabilities']
        except Exception as e:
            result['error'] = str(e)
        return result

    def _test_pop3(self, ip, port):
        """Test POP3 service"""
        result = {}
        try:
            if port == 995:  # POP3S
                context = ssl.create_default_context()
                with poplib.POP3_SSL(ip, port, timeout=5, context=context) as pop3:
                    result['banner'] = pop3.getwelcome().decode('utf-8', errors='ignore')
            else:  # POP3 (110)
                with poplib.POP3(ip, port, timeout=5) as pop3:
                    result['banner'] = pop3.getwelcome().decode('utf-8', errors='ignore')
                    try:
                        pop3.capa()
                        result['stls'] = True
                    except:
                        result['stls'] = False
        except Exception as e:
            result['error'] = str(e)
        return result

    def _get_banner(self, ip, port, timeout=2):
        """Get service banner"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                return s.recv(1024).decode('utf-8', errors='ignore').strip()
        except Exception as e:
            return f"Error: {str(e)}"

    def generate_reports(self):
        """Generate various reports"""
        self._generate_traffic_report()
        self._generate_alert_report()
        self._generate_service_report()
        self._generate_visualizations()

    def _generate_traffic_report(self):
        """Generate traffic statistics report"""
        filename = f"traffic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Source IP', 'Destination IP', 'Port', 'Service', 'Packets', 'Bytes', 'Last Activity'])
            
            for (src, dst, port), stats in self.traffic_stats.items():
                service = self._identify_service(port)
                writer.writerow([src, dst, port, service, stats['packets'], stats['bytes'], stats.get('last_activity', '')])
        
        logging.info(f"Traffic report generated: {filename}")

    def _generate_alert_report(self):
        """Generate alert report"""
        if not self.alerts:
            logging.info("No alerts to report")
            return
            
        filename = f"alert_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(self.alerts, f, indent=4)
        
        logging.info(f"Alert report generated: {filename}")

    def _generate_service_report(self):
        """Generate service test report"""
        # This would be populated after running service tests
        pass

    def _generate_visualizations(self):
        """Generate traffic visualizations"""
        if not self.traffic_stats:
            logging.info("No traffic data to visualize")
            return
            
        # Prepare data
        data = []
        for (src, dst, port), stats in self.traffic_stats.items():
            data.append({
                'source': src,
                'destination': dst,
                'port': port,
                'service': self._identify_service(port),
                'packets': stats['packets'],
                'bytes': stats['bytes']
            })
        
        df = pd.DataFrame(data)
        
        # Top talkers plot
        plt.figure(figsize=(12, 6))
        df.groupby('source')['packets'].sum().nlargest(10).plot(kind='bar')
        plt.title('Top 10 Email Clients by Packet Count')
        plt.ylabel('Packets')
        plt.tight_layout()
        plt.savefig('top_clients.png')
        plt.close()

        # Service distribution plot
        plt.figure(figsize=(12, 6))
        df.groupby('service')['bytes'].sum().plot(kind='pie', autopct='%1.1f%%')
        plt.title('Email Traffic Distribution by Service')
        plt.ylabel('')
        plt.tight_layout()
        plt.savefig('service_distribution.png')
        plt.close()

        logging.info("Visualizations generated: top_clients.png, service_distribution.png")

def main():
    parser = argparse.ArgumentParser(description="Email Traffic Monitoring Tool")
    parser.add_argument('-i', '--interface', help="Network interface to monitor")
    parser.add_argument('-d', '--duration', type=int, default=0,
                        help="Duration of capture in seconds (0 for unlimited)")
    parser.add_argument('-t', '--target', help="Test specific IP address")
    args = parser.parse_args()

    monitor = EmailTrafficMonitor()

    if args.target:
        # Test specific IP
        results = monitor.test_email_services(args.target)
        print(json.dumps(results, indent=2))
        with open(f"service_test_{args.target}.json", 'w') as f:
            json.dumps(results, f, indent=2)
    elif args.interface:
        # Live monitoring
        capture_thread, alert_thread = monitor.start_live_capture(
            args.interface,
            args.duration
        )
        capture_thread.join()
        alert_thread.join()
        monitor.generate_reports()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()