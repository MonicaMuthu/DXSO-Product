import imaplib
import email
import re
import getpass
import json
import subprocess
import tempfile
from email.parser import BytesParser
from email import policy
from collections import Counter
from datetime import datetime

def scan_email_account():
    imap_server = "imap.gmail.com"
    email_user = input("Enter your email address: ")
    email_pass = getpass.getpass("Enter your app password: ")

    print("\n🔍 Connecting to server...")
    conn = imaplib.IMAP4_SSL(imap_server)
    conn.login(email_user, email_pass)
    conn.select('inbox')

    typ, data = conn.search(None, 'ALL')
    email_ids = data[0].split()
    emails = []

    print(f"📥 Fetching {len(email_ids)} emails...")
    for num in email_ids[-100:]:  # Last 100 emails
        typ, msg_data = conn.fetch(num, '(RFC822)')
        raw_email = msg_data[0][1]
        msg = BytesParser(policy=policy.default).parsebytes(raw_email)
        emails.append((msg, raw_email))

    stats = []
    date_counter = Counter()

    for msg, raw in emails:
        subject = msg.get("Subject", "")
        sender = msg.get("From", "")
        date = msg.get("Date", "")
        received = msg.get("Received", "")

        try:
            body = msg.get_body(preferencelist=('plain', 'html')).get_content()
        except:
            body = str(msg.get_payload())

        keywords = ["confidential", "password", "urgent"]
        found_keywords = [kw for kw in keywords if kw in body.lower()]

        dlp_matches = re.findall(r'\b\d{16}\b|\b\d{3}-\d{2}-\d{4}\b', body)
        phishing_links = re.findall(r'https?://[^ ]+', body)
        phishing_links = [u for u in phishing_links if 'login' in u or 'verify' in u]

        oversized = []
        for part in msg.iter_attachments():
            content = part.get_payload(decode=True)
            if content and len(content) > 1024 * 1024:
                oversized.append((part.get_filename(), round(len(content)/1024, 2)))

        domains = set(re.findall(r'@([A-Za-z0-9.-]+)', str(msg)))
        encrypted = 'TLS' in received
        bounce = "Delivery Status Notification" in subject
        compliant = "This email is confidential" in body

        msg_date = None
        try:
            msg_date = datetime.strptime(date, '%a, %d %b %Y %H:%M:%S %z').date()
            date_counter[msg_date] += 1
        except:
            pass

        # Rspamd Scan
        with tempfile.NamedTemporaryFile(delete=True) as temp_eml:
            temp_eml.write(raw)
            temp_eml.flush()
            try:
                rspamd_result = subprocess.run(['rspamc', '-j', temp_eml.name], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                rspamd_output = json.loads(rspamd_result.stdout.decode())
            except:
                rspamd_output = {"error": "Rspamd scan failed"}

        activity = {
            "Subject": subject,
            "From": sender,
            "Date": date,
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
        stats.append(activity)

    print("\n📊 Email Activity Report:")
    for s in stats:
        print(f"\n📧 {s['Subject']}")
        print(f"From: {s['From']}, Date: {s['Date']}")
        print(f"Bounce: {s['Bounce']}, Encrypted: {s['Encrypted']}, Compliant: {s['Compliant']}")
        print(f"Keywords: {s['Keywords Found']}, DLP: {s['DLP Matches']}, Phishing: {s['Phishing Links']}")
        print(f"Oversized Attachments: {s['Oversized Attachments']}")
        print(f"Recipient Domains: {s['Recipient Domains']}")
        print(f"Rspamd Report: {json.dumps(s['Rspamd Report'], indent=2)}")

    print("\n📅 Historical Email Traffic:")
    for day, count in date_counter.items():
        print(f"{day}: {count} emails")

    with open("email_activity_report.json", "w") as f:
        json.dump(stats, f, indent=2)
    print("\n✅ Report saved to email_activity_report.json")

if __name__ == "__main__":
    scan_email_account()
