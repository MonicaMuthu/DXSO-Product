import imaplib
import email
import re
import getpass
import json
import subprocess
import tempfile
from email.parser import BytesParser
from email import policy
from collections import Counter, defaultdict
from datetime import datetime

def send_alert(subject, body):
    # 🔔 Real-Time Alerts
    print(f"\n🚨 ALERT: {subject}\n{body}\n")

class EmailMonitor:
    def __init__(self):
        self.imap_server = "imap.gmail.com"
        self.email_user = input("Enter your email address: ")
        self.email_pass = getpass.getpass("Enter your app password: ")
        self.conn = None
        self.stats = []
        self.date_counter = Counter()  # 📊 Historical Email Traffic Reports
        self.behavior_metrics = defaultdict(int)  # 👤 User Behavior Monitoring

    def connect(self):
        self.conn = imaplib.IMAP4_SSL(self.imap_server)
        self.conn.login(self.email_user, self.email_pass)
        self.conn.select('inbox')

    def fetch_emails(self):
        typ, data = self.conn.search(None, 'ALL')
        email_ids = data[0].split()
        emails = []
        for num in email_ids[-100:]:
            typ, msg_data = self.conn.fetch(num, '(RFC822)')
            raw_email = msg_data[0][1]
            msg = BytesParser(policy=policy.default).parsebytes(raw_email)
            emails.append((msg, raw_email))
        return emails

    def scan_email(self, msg, raw):
        subject = msg.get("Subject", "")
        sender = msg.get("From", "")
        date = msg.get("Date", "")
        received = msg.get("Received", "")  # 📬 Header Analysis

        try:
            body = msg.get_body(preferencelist=('plain', 'html')).get_content()
        except:
            body = str(msg.get_payload())

        # 🔍 Keyword-Based Filtering
        keywords = ["confidential", "password", "urgent"]
        found_keywords = [kw for kw in keywords if kw in body.lower()]

        # 🔐 Data Loss Prevention (DLP)
        dlp_matches = re.findall(r'\b\d{16}\b|\b\d{3}-\d{2}-\d{4}\b', body)

        # 🧪 Phishing Detection
        phishing_links = [u for u in re.findall(r'https?://[^ ]+', body) if 'login' in u or 'verify' in u]

        # 📎 Attachment Scanning
        oversized = []
        for part in msg.iter_attachments():
            content = part.get_payload(decode=True)
            if content and len(content) > 1024 * 1024:
                oversized.append((part.get_filename(), round(len(content)/1024, 2)))  # 📏 Attachment Size Monitoring

        # 📫 Recipient/Domain Tracking
        domains = set(re.findall(r'@([A-Za-z0-9.-]+)', str(msg)))

        # 🔐 Encryption Validation
        encrypted = 'TLS' in received

        # 📤 Email Bounce Analysis
        bounce = "Delivery Status Notification" in subject

        # ✅ Compliance Monitoring
        compliant = "This email is confidential" in body

        # 🕒 Historical Traffic & Behavior
        try:
            msg_date = datetime.strptime(date, '%a, %d %b %Y %H:%M:%S %z').date()
            self.date_counter[msg_date] += 1
            self.behavior_metrics[msg_date] += 1
        except:
            msg_date = "Unknown"

        # 🤖 Spam Detection using rspamc
        with tempfile.NamedTemporaryFile(delete=True) as temp_eml:
            temp_eml.write(raw)
            temp_eml.flush()
            try:
                rspamd_result = subprocess.run(['rspamc', '-j', temp_eml.name], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                rspamd_output = json.loads(rspamd_result.stdout.decode())
            except:
                rspamd_output = {"error": "Rspamd scan failed"}

        if rspamd_output.get('action') in ['reject', 'add header']:
            send_alert("Spam Detected", subject)

        if phishing_links:
            send_alert("Phishing Attempt", f"Subject: {subject}\nLinks: {phishing_links}")

        activity = {
            "Subject": subject,
            "From": sender,
            "Date": str(msg_date),
            "Bounce": bounce,
            "Encrypted": encrypted,
            "Phishing Links": phishing_links,
            "Keywords Found": found_keywords,
            "DLP Matches": dlp_matches,
            "Oversized Attachments": oversized,
            "Compliant": compliant,
            "Recipient Domains": list(domains),
            "Rspamd Report": rspamd_output
        }
        self.stats.append(activity)

    def monitor(self):
        self.connect()
        emails = self.fetch_emails()
        for msg, raw in emails:
            self.scan_email(msg, raw)
        self.report()

    def report(self):
        print("\n📊 Email Activity Report:")
        for s in self.stats:
            print(f"\n📧 {s['Subject']}\nFrom: {s['From']}, Date: {s['Date']}")
            print(f"Bounce: {s['Bounce']}, Encrypted: {s['Encrypted']}, Compliant: {s['Compliant']}")
            print(f"Keywords: {s['Keywords Found']}, DLP: {s['DLP Matches']}, Phishing: {s['Phishing Links']}")
            print(f"Oversized Attachments: {s['Oversized Attachments']}, Recipient Domains: {s['Recipient Domains']}")
            print(f"Rspamd Report: {json.dumps(s['Rspamd Report'], indent=2)}")

        print("\n📅 Historical Email Traffic:")
        for day, count in self.date_counter.items():
            print(f"{day}: {count} emails")

        threshold = sum(self.behavior_metrics.values()) / (len(self.behavior_metrics) or 1)
        for day, count in self.behavior_metrics.items():
            if count > threshold * 1.5:
                send_alert("User Behavior Anomaly", f"High email volume on {day}: {count} emails")

        with open("email_activity_report.json", "w") as f:
            json.dump(self.stats, f, indent=2)
        print("\n✅ Report saved to email_activity_report.json")

if __name__ == "__main__":
    monitor = EmailMonitor()
    monitor.monitor()
