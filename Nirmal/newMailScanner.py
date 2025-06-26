import imaplib
import email
import re
import getpass
import smtplib
import subprocess
import tempfile
import json
from email.parser import BytesParser
from email.mime.text import MIMEText
from email import policy
from collections import defaultdict, Counter
from datetime import datetime, timedelta

class EmailSecurityMonitor:
    def __init__(self):
        # Configuration
        self.imap_server = "imap.gmail.com"
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        self.email_user = input("Enter your email address: ")
        self.email_pass = getpass.getpass("Enter your app password: ")
        
        # Monitoring data
        self.report_data = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'stats': {
                'total_emails': 0,
                'spam_count': 0,
                'phishing_count': 0,
                'dlp_violations': 0,
                'malicious_attachments': 0,
                'oversized_attachments': 0,
                'encrypted_emails': 0,
                'compliance_violations': 0,
                'unique_senders': set(),
                'bounced_emails': 0,
                'user_actions': defaultdict(dict),
                'daily_counts': defaultdict(int)
            },
            'alerts': [],
            'email_details': []
        }
        self.conn = None

    def connect(self):
        """Establish IMAP connection"""
        try:
            self.conn = imaplib.IMAP4_SSL(self.imap_server)
            self.conn.login(self.email_user, self.email_pass)
            self.conn.select('inbox')
            return True
        except Exception as e:
            self.add_alert("Connection Failed", f"Could not connect to email server: {str(e)}", "critical")
            return False

    def fetch_emails(self, limit=50):
        """Fetch recent emails"""
        try:
            typ, data = self.conn.search(None, 'ALL')
            email_ids = data[0].split()
            return email_ids[-limit:]
        except Exception as e:
            self.add_alert("Fetch Failed", f"Could not fetch emails: {str(e)}", "critical")
            return []

    def scan_email(self, msg, raw_email):
        """Enhanced email scanning with all requested tracking"""
        try:
            email_date = datetime.strptime(msg.get('Date'), '%a, %d %b %Y %H:%M:%S %z').date()
            date_str = email_date.strftime('%Y-%m-%d')
            self.report_data['stats']['daily_counts'][date_str] += 1
            
            try:
                body = msg.get_body(preferencelist=('plain', 'html')).get_content()
            except:
                body = str(msg.get_payload())

            # Check for bounce before full processing
            is_bounce = self.check_bounce(msg, body)
            if is_bounce:
                self.report_data['stats']['bounced_emails'] += 1
                self.add_alert("Bounced Email", msg.get('Subject', 'No Subject'), "medium")

            email_info = {
                'subject': msg.get('Subject', 'No Subject'),
                'from': msg.get('From', 'Unknown'),
                'date': msg.get('Date', 'Unknown'),
                'headers': self.analyze_headers(msg),
                'attachments': self.scan_attachments(msg),
                'spam': self.detect_spam(raw_email),
                'phishing': self.detect_phishing(msg, body),
                'dlp': self.dlp_scan(body),
                'keywords': self.keyword_filtering(body),
                'compliance': self.check_compliance(msg, body),
                'bounce': is_bounce,
                'user_actions': self.track_user_actions(msg)
            }
            
            # Update statistics
            if email_info['spam']['is_spam']:
                self.report_data['stats']['spam_count'] += 1
                self.add_alert("Spam Detected", email_info['subject'], "high")
                
            if email_info['phishing']['suspicious']:
                self.report_data['stats']['phishing_count'] += 1
                self.add_alert("Phishing Attempt", email_info['subject'], "high")
                
            if email_info['dlp']:
                self.report_data['stats']['dlp_violations'] += len(email_info['dlp'])
                self.add_alert("DLP Violation", f"{email_info['subject']} - {list(email_info['dlp'].keys())}", "medium")
                
            if email_info['attachments']['malicious']:
                self.report_data['stats']['malicious_attachments'] += 1
                self.add_alert("Malicious Attachment", f"{email_info['subject']} - {email_info['attachments']['malicious_files']}", "critical")
                
            if email_info['attachments']['oversized']:
                self.report_data['stats']['oversized_attachments'] += 1
                self.add_alert("Oversized Attachment", f"{email_info['subject']} - {email_info['attachments']['oversized_files']}", "medium")
                
            if email_info['headers']['encrypted']:
                self.report_data['stats']['encrypted_emails'] += 1
                
            if not all(email_info['compliance'].values()):
                self.report_data['stats']['compliance_violations'] += 1
                self.add_alert("Compliance Violation", email_info['subject'], "medium")
                
            self.report_data['stats']['unique_senders'].add(email_info['from'])
            self.report_data['stats']['total_emails'] += 1
            
            self.report_data['email_details'].append(email_info)
        except Exception as e:
            self.add_alert("Scan Error", f"Error processing email: {str(e)}", "high")

    def check_bounce(self, msg, body):
        """Detect bounced emails"""
        bounce_indicators = [
            'undelivered mail',
            'returned mail',
            'delivery status notification',
            'failure notice',
            'mail delivery failed'
        ]
        
        subject = msg.get('Subject', '').lower()
        body = body.lower()
        
        # Check subject and first part of body
        if any(indicator in subject for indicator in bounce_indicators):
            return True
            
        if any(indicator in body[:500] for indicator in bounce_indicators):
            return True
            
        # Check for specific headers
        if msg.get('X-Failed-Recipients'):
            return True
            
        return False

    def track_user_actions(self, msg):
        """Track user interactions with emails (simulated)"""
        # In a real implementation, this would integrate with your email client's API
        # or tracking pixels/links for opens and clicks
        
        # Simulating some basic tracking
        message_id = msg.get('Message-ID', 'unknown')
        return {
            'opened': self.simulate_email_open(message_id),
            'links_clicked': self.simulate_link_clicks(message_id)
        }

    def simulate_email_open(self, message_id):
        """Simulate email open tracking (would be real API calls in production)"""
        # 80% chance of being opened for demonstration purposes
        return random.random() < 0.8

    def simulate_link_clicks(self, message_id):
        """Simulate link click tracking (would be real API calls in production)"""
        # Randomly generate 0-2 clicks for demonstration
        num_clicks = random.randint(0, 2)
        return [f"link_{i+1}" for i in range(num_clicks)]

    def analyze_headers(self, msg):
        """Detailed header analysis"""
        received = msg.get_all('Received', [])
        return {
            'spf_pass': not any('spf=fail' in h.lower() for h in received),
            'dkim_pass': not any('dkim=fail' in h.lower() for h in received),
            'encrypted': any('TLS' in h for h in received)
        }

    def scan_attachments(self, msg):
        """Enhanced attachment scanning with size tracking"""
        result = {
            'count': 0,
            'malicious': False,
            'oversized': False,
            'malicious_files': [],
            'oversized_files': [],
            'sizes': {}
        }
        
        for part in msg.iter_attachments():
            filename = part.get_filename() or f"attachment_{result['count']}"
            content = part.get_payload(decode=True)
            size = len(content) if content else 0
            result['sizes'][filename] = size
            
            # Check for malicious extensions
            is_malicious = any(filename.lower().endswith(ext) 
                          for ext in ['.exe', '.bat', '.js', '.vbs', '.ps1', '.scr'])
            
            # Check for oversized (10MB threshold)
            is_oversized = size > 10 * 1024 * 1024
            
            if is_malicious:
                result['malicious_files'].append(f"{filename} ({size/1024:.2f}KB)")
                result['malicious'] = True
            if is_oversized:
                result['oversized_files'].append(f"{filename} ({size/1024/1024:.2f}MB)")
                result['oversized'] = True
                
            result['count'] += 1
            
        return result

    def detect_spam(self, raw_email):
        """Check for spam using Rspamd"""
        result = {'is_spam': False, 'score': 0, 'details': 'Not scanned'}
        with tempfile.NamedTemporaryFile(delete=True) as temp_eml:
            temp_eml.write(raw_email)
            temp_eml.flush()
            try:
                rspamd_result = subprocess.run(
                    ['rspamc', '-j', temp_eml.name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                if rspamd_result.returncode == 0:
                    output = json.loads(rspamd_result.stdout.decode())
                    result = {
                        'is_spam': output.get('action') in ['reject', 'add header'],
                        'score': output.get('score', 0),
                        'details': output
                    }
            except Exception as e:
                result['details'] = f"Scan failed: {str(e)}"
        return result

    def detect_phishing(self, msg, body):
        """Detect phishing attempts"""
        links = re.findall(r'https?://[^\s<>"\']+', body)
        suspicious_links = [
            link for link in links 
            if re.search(r'(login|verify|secure|account)', link, re.IGNORECASE)
            and not re.search(r'\.(com|org|net|gov)\b', link)
        ]
        
        sender = msg.get('From', '')
        impersonation = bool(
            re.search(r'(support|admin|security)', sender, re.IGNORECASE) and
            not re.search(r'@(gmail|yahoo|outlook)\.', sender, re.IGNORECASE)
        )
        
        urgency = bool(
            re.search(r'(urgent|immediate|action required)', 
                     msg.get('Subject', ''), re.IGNORECASE)
        )
        
        return {
            'suspicious': bool(suspicious_links or impersonation or urgency),
            'suspicious_links': suspicious_links,
            'impersonation': impersonation,
            'urgency': urgency
        }

    def dlp_scan(self, body):
        """Data Loss Prevention scan"""
        patterns = {
            'credit_card': r'\b(?:\d[ -]*?){13,16}\b',
            'ssn': r'\b\d{3}[ -]?\d{2}[ -]?\d{4}\b',
            'phone': r'\b(?:\+?1[ -]?)?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}\b'
        }
        found = {}
        for name, pattern in patterns.items():
            matches = re.findall(pattern, body)
            if matches:
                found[name] = matches[:3]  # Limit to first 3 matches
        return found

    def keyword_filtering(self, body):
        """Check for keywords"""
        keywords = {
            'confidential': ['confidential', 'secret', 'classified'],
            'financial': ['account', 'payment', 'invoice', 'bank'],
            'urgent': ['urgent', 'immediate', 'asap']
        }
        found = {}
        for category, words in keywords.items():
            matches = [w for w in words if re.search(r'\b' + w + r'\b', body, re.IGNORECASE)]
            if matches:
                found[category] = matches
        return found

    def check_compliance(self, msg, body):
        """Detailed compliance checks"""
        return {
            'disclaimer': 'confidential' in body.lower(),
            'proper_subject': bool(re.match(r'^[\w\s-]+$', msg.get('Subject', '')))
        }

    def add_alert(self, title, message, severity="medium"):
        """Add an alert to the report"""
        self.report_data['alerts'].append({
            'title': title,
            'message': message,
            'severity': severity,
            'timestamp': datetime.now().strftime("%H:%M:%S")
        })

    def generate_text_report(self):
        """Generate enhanced human-readable text report"""
        report = []
        
        # Header
        report.append("="*80)
        report.append(f"COMPREHENSIVE EMAIL SECURITY MONITORING REPORT".center(80))
        report.append(f"Generated: {self.report_data['timestamp']}".center(80))
        report.append(f"Account: {self.email_user}".center(80))
        report.append("="*80)
        report.append("\n")
        
        # Summary
        report.append("[SUMMARY STATISTICS]")
        report.append(f"Total Emails Scanned: {self.report_data['stats']['total_emails']}")
        report.append(f"Spam Detected: {self.report_data['stats']['spam_count']}")
        report.append(f"Phishing Attempts: {self.report_data['stats']['phishing_count']}")
        report.append(f"DLP Violations: {self.report_data['stats']['dlp_violations']}")
        report.append(f"Malicious Attachments: {self.report_data['stats']['malicious_attachments']}")
        report.append(f"Oversized Attachments: {self.report_data['stats']['oversized_attachments']}")
        report.append(f"Encrypted Emails: {self.report_data['stats']['encrypted_emails']}")
        report.append(f"Compliance Violations: {self.report_data['stats']['compliance_violations']}")
        report.append(f"Bounced Emails: {self.report_data['stats']['bounced_emails']}")
        report.append(f"Unique Senders: {len(self.report_data['stats']['unique_senders'])}")
        report.append("\n")
        
        # Historical Traffic
        report.append("[HISTORICAL TRAFFIC PATTERNS]")
        sorted_dates = sorted(self.report_data['stats']['daily_counts'].items())
        for date, count in sorted_dates[-7:]:  # Last 7 days
            report.append(f"{date}: {count} emails")
        report.append("\n")
        
        # Alerts
        if self.report_data['alerts']:
            report.append("[SECURITY ALERTS]")
            for alert in self.report_data['alerts']:
                severity = alert['severity'].upper()
                report.append(f"{severity}: {alert['title']} - {alert['message']} ({alert['timestamp']})")
            report.append("\n")
        
        # Detailed Findings
        report.append("[DETAILED EMAIL ANALYSIS]")
        for email in self.report_data['email_details']:
            report.append("\n" + "-"*80)
            report.append(f"Subject: {email['subject']}")
            report.append(f"From: {email['from']}")
            report.append(f"Date: {email['date']}")
            
            # Header Analysis
            report.append("\nHEADER ANALYSIS:")
            report.append(f"  SPF: {'PASS' if email['headers']['spf_pass'] else 'FAIL'}")
            report.append(f"  DKIM: {'PASS' if email['headers']['dkim_pass'] else 'FAIL'}")
            report.append(f"  Encryption: {'TLS Encrypted' if email['headers']['encrypted'] else 'Unencrypted'}")
            
            # Attachments
            report.append("\nATTACHMENTS:")
            if email['attachments']['count'] > 0:
                report.append(f"  Total: {email['attachments']['count']}")
                if email['attachments']['malicious']:
                    report.append("  MALICIOUS FILES DETECTED:")
                    for f in email['attachments']['malicious_files']:
                        report.append(f"    - {f}")
                else:
                    report.append("  No malicious attachments detected")
                
                if email['attachments']['oversized']:
                    report.append("  OVERSIZED FILES DETECTED:")
                    for f in email['attachments']['oversized_files']:
                        report.append(f"    - {f}")
                else:
                    report.append("  No oversized attachments detected")
                
                # Attachment size statistics
                if email['attachments']['sizes']:
                    report.append("  SIZE STATISTICS:")
                    total_size = sum(email['attachments']['sizes'].values()) / 1024
                    avg_size = total_size / len(email['attachments']['sizes'])
                    report.append(f"    Total size: {total_size:.2f} KB")
                    report.append(f"    Average size: {avg_size:.2f} KB")
            else:
                report.append("  No attachments found")
            
            # Security Checks
            report.append("\nSECURITY CHECKS:")
            if email['spam']['is_spam']:
                report.append(f"  SPAM: Detected (Score: {email['spam']['score']})")
            else:
                report.append("  SPAM: No detection")
                
            if email['phishing']['suspicious']:
                report.append("  PHISHING: Detected")
                report.append(f"    Suspicious Links: {len(email['phishing']['suspicious_links'])}")
                report.append(f"    Impersonation: {'Yes' if email['phishing']['impersonation'] else 'No'}")
                report.append(f"    Urgency Indicators: {'Yes' if email['phishing']['urgency'] else 'No'}")
            else:
                report.append("  PHISHING: No detection")
                
            if email['dlp']:
                report.append("  DLP VIOLATIONS:")
                for pattern, matches in email['dlp'].items():
                    report.append(f"    {pattern.upper()}: {len(matches)} found")
            else:
                report.append("  DLP: No violations")
                
            if email['keywords']:
                report.append("  KEYWORDS FOUND:")
                for category, words in email['keywords'].items():
                    report.append(f"    {category.upper()}: {', '.join(words)}")
            else:
                report.append("  KEYWORDS: No matches")
            
            # Compliance
            report.append("\nCOMPLIANCE CHECK:")
            report.append(f"  Disclaimer Present: {'Yes' if email['compliance']['disclaimer'] else 'No'}")
            report.append(f"  Proper Subject: {'Yes' if email['compliance']['proper_subject'] else 'No'}")
            report.append(f"  Fully Compliant: {'Yes' if all(email['compliance'].values()) else 'No'}")
            
            # Bounce and User Actions
            report.append("\nDELIVERY & ENGAGEMENT:")
            report.append(f"  Bounced: {'Yes' if email['bounce'] else 'No'}")
            report.append(f"  Opened: {'Yes' if email['user_actions']['opened'] else 'No'}")
            if email['user_actions']['links_clicked']:
                report.append(f"  Links Clicked: {len(email['user_actions']['links_clicked'])}")
            else:
                report.append("  Links Clicked: None")
        
        report.append("\n" + "="*80)
        report.append("END OF REPORT".center(80))
        report.append("="*80)
        
        return "\n".join(report)

    def save_report(self, filename="email_security_report.txt"):
        """Save the report to a text file"""
        report_text = self.generate_text_report()
        with open(filename, 'w') as f:
            f.write(report_text)
        print(f"\nReport saved to {filename}")

    def run_monitoring(self):
        """Execute complete monitoring workflow"""
        if not self.connect():
            return
            
        email_ids = self.fetch_emails()
        if not email_ids:
            return
            
        for email_id in email_ids:
            typ, msg_data = self.conn.fetch(email_id, '(RFC822)')
            raw_email = msg_data[0][1]
            msg = BytesParser(policy=policy.default).parsebytes(raw_email)
            self.scan_email(msg, raw_email)
        
        self.save_report()
        self.conn.close()
        self.conn.logout()

if __name__ == "__main__":
    import random  # Needed for simulated user tracking
    print("📧 ENHANCED EMAIL SECURITY MONITORING SYSTEM")
    print("="*50)
    
    monitor = EmailSecurityMonitor()
    monitor.run_monitoring()