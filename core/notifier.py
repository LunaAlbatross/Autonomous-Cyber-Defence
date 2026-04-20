import os
import smtplib
import threading
from email.message import EmailMessage
from datetime import datetime

# Default to the target email provided by the user
TARGET_EMAIL = "tkowshik06@gmail.com"

def _send_email_async(ip, threat_type, details):
    sender_email = os.environ.get("WAF_SENDER_EMAIL")
    sender_password = os.environ.get("WAF_SENDER_PASSWORD")

    if not sender_email or not sender_password:
        print("[!] Email Alert Warning: Missing WAF_SENDER_EMAIL or WAF_SENDER_PASSWORD in environment.")
        print("[!] Ignoring email dispatch.")
        return

    msg = EmailMessage()
    msg['Subject'] = f"🚨 WAF ALERT: IP Quarantined [{ip}]"
    msg['From'] = f"Autonomous Cyber Defence <{sender_email}>"
    msg['To'] = TARGET_EMAIL

    body = f"""AUTONOMOUS CYBER DEFENCE - SECURITY ALERT
=========================================

A fatal security violation was intercepted by the Web Application Firewall.
The offending IP Address has been actively banned and quarantined.

Incident Details:
-----------------
Timestamp   : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Attacker IP : {ip}
Threat Type : {threat_type}
Payload     : {details}

Immediate action is not required. The firewall has successfully neutralized the threat.
"""
    msg.set_content(body)

    try:
        # Assuming Gmail SMTP for generic default
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender_email, sender_password)
            smtp.send_message(msg)
        print(f"[*] Alert Email sent successfully to {TARGET_EMAIL}")
    except Exception as e:
        print(f"[!] Critical Error sending email alert: {e}")

def send_alert(ip, threat_type, details):
    """ Fire off the email alert in a separate background thread so it doesn't block proxy traffic. """
    thread = threading.Thread(target=_send_email_async, args=(ip, threat_type, details))
    thread.daemon = True
    thread.start()
