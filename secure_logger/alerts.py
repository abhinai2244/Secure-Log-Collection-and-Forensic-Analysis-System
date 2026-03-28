import requests
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class AlertManager:
    """
    Manages multiple alert channels: Telegram, Email, and System Logs.
    """
    def __init__(self, telegram_token=None, telegram_chat_id=None, email_config=None):
        self.telegram_token = telegram_token
        self.telegram_chat_id = telegram_chat_id
        self.email_config = email_config # {smtp_server, smtp_port, email, password, to_email}

    def dispatch(self, alert_type, details, risk_score):
        """Sends alerts across all configured channels."""
        severity = "CRITICAL" if risk_score > 0.8 else "WARNING"
        message = (
            f"⚠ [SECURITY ALERT: {severity}]\n"
            f"Type: {alert_type}\n"
            f"Risk Score: {risk_score}\n"
            f"Details: {details}\n"
            f"Time: {json.dumps(details)}" # Placeholder for formatted time
        )

        # 1. System Log (Always)
        print(f"\n[ALERT MANAGER] {message}\n")

        # 2. Telegram
        if self.telegram_token and self.telegram_chat_id:
            self._send_telegram(message)

        # 3. Email
        if self.email_config:
            self._send_email(f"Security Alert: {alert_type}", message)

    def _send_telegram(self, message):
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {
            "chat_id": self.telegram_chat_id,
            "text": message,
            "parse_mode": "HTML"
        }
        try:
            requests.post(url, json=payload, timeout=5)
        except Exception as e:
            print(f"[Alert System] Telegram error: {e}")

    def _send_email(self, subject, body):
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_config['email']
            msg['To'] = self.email_config['to_email']
            msg['Subject'] = subject

            msg.attach(MIMEText(body, 'plain'))

            server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
            server.starttls()
            server.login(self.email_config['email'], self.email_config['password'])
            server.send_message(msg)
            server.quit()
        except Exception as e:
            print(f"[Alert System] Email error: {e}")
