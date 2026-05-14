"""
email_notifier.py — Sends email notifications for HIGH/CRITICAL alerts.

• Polls DB every 60 seconds for unsent alerts
• Sends HTML email with alert details + AI explanation
• Marks alert as email_sent to avoid duplicate sends

Requires in .env:
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, ALERT_EMAIL

Run:  python email_notifier.py
"""
import os
import time
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from models.db import get_conn

from dotenv import load_dotenv
load_dotenv()

POLL_INTERVAL   = 60
NOTIFY_SEVERITIES = {"HIGH", "CRITICAL"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [email_notifier] %(levelname)s %(message)s"
)
log = logging.getLogger("email_notifier")


# ── DB: add email_sent column if missing ──────────────────────────────────

def ensure_email_column():
    sql = """
        ALTER TABLE alerts
        ADD COLUMN IF NOT EXISTS email_sent BOOLEAN DEFAULT FALSE;
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)


def fetch_unsent_alerts() -> list[dict]:
    sql = """
        SELECT id, rule_name, severity, title, description,
               ai_explanation, related_ips, related_users,
               event_count, created_at
        FROM   alerts
        WHERE  is_resolved = FALSE
          AND  email_sent  = FALSE
          AND  severity    = ANY(%s)
        ORDER  BY created_at DESC
        LIMIT  5
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (list(NOTIFY_SEVERITIES),))
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]


def mark_email_sent(alert_id: int):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE alerts SET email_sent = TRUE WHERE id = %s",
                (alert_id,)
            )


# ── Email HTML template ───────────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": "#A32D2D",
    "HIGH":     "#854F0B",
    "MEDIUM":   "#185FA5",
    "LOW":      "#0F6E56",
}

def build_html(alert: dict) -> str:
    color      = SEVERITY_COLORS.get(alert['severity'], "#444")
    ips        = ', '.join(alert['related_ips'] or []) or 'None detected'
    users      = ', '.join(alert['related_users'] or []) or 'None'
    ai_block   = alert['ai_explanation'] or 'AI analysis pending...'
    # Convert newlines to <br> for HTML
    ai_html    = ai_block.replace('\n', '<br>')
    detected   = alert['created_at']

    return f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;background:#f5f5f5;padding:20px">
  <div style="max-width:600px;margin:0 auto;background:#fff;
              border-radius:8px;overflow:hidden;
              border:1px solid #e0e0e0">

    <!-- Header -->
    <div style="background:{color};padding:20px 24px">
      <h1 style="color:#fff;margin:0;font-size:18px">
        🚨 SIEM Alert — {alert['severity']}
      </h1>
      <p style="color:rgba(255,255,255,0.85);margin:6px 0 0;font-size:13px">
        {detected}
      </p>
    </div>

    <!-- Body -->
    <div style="padding:24px">
      <h2 style="margin:0 0 8px;font-size:16px;color:#222">
        {alert['title']}
      </h2>
      <p style="color:#555;font-size:14px;margin:0 0 20px">
        {alert['description'] or ''}
      </p>

      <!-- Details table -->
      <table style="width:100%;border-collapse:collapse;font-size:13px;
                    margin-bottom:20px">
        <tr style="background:#f9f9f9">
          <td style="padding:8px 12px;color:#777;width:140px">Rule</td>
          <td style="padding:8px 12px;color:#222">{alert['rule_name']}</td>
        </tr>
        <tr>
          <td style="padding:8px 12px;color:#777">Events count</td>
          <td style="padding:8px 12px;color:#222">{alert['event_count']}</td>
        </tr>
        <tr style="background:#f9f9f9">
          <td style="padding:8px 12px;color:#777">IPs involved</td>
          <td style="padding:8px 12px;color:#c0392b;font-family:monospace">
            {ips}
          </td>
        </tr>
        <tr>
          <td style="padding:8px 12px;color:#777">Users targeted</td>
          <td style="padding:8px 12px;color:#222">{users}</td>
        </tr>
      </table>

      <!-- AI explanation -->
      <div style="background:#f0f4ff;border-left:4px solid #185FA5;
                  border-radius:4px;padding:16px;margin-bottom:20px">
        <p style="margin:0 0 8px;font-size:12px;font-weight:bold;
                  color:#185FA5;text-transform:uppercase;
                  letter-spacing:0.5px">
          🤖 Claude AI Analysis
        </p>
        <p style="margin:0;font-size:13px;color:#333;line-height:1.6">
          {ai_html}
        </p>
      </div>

      <!-- Action button -->
      <div style="text-align:center;margin-top:20px">
        <a href="http://localhost:5000/api/alerts/{alert['id']}"
           style="background:{color};color:#fff;padding:10px 24px;
                  text-decoration:none;border-radius:6px;font-size:14px">
          View Alert in Dashboard →
        </a>
      </div>
    </div>

    <!-- Footer -->
    <div style="background:#f9f9f9;padding:12px 24px;
                border-top:1px solid #e0e0e0;text-align:center">
      <p style="margin:0;font-size:11px;color:#999">
        SIEM Project — Automated Security Alert
      </p>
    </div>
  </div>
</body>
</html>"""


# ── Send email ────────────────────────────────────────────────────────────

def send_email(alert: dict) -> bool:
    smtp_host  = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port  = int(os.getenv("SMTP_PORT", 587))
    smtp_user  = os.getenv("SMTP_USER", "")
    smtp_pass  = os.getenv("SMTP_PASS", "")
    to_email   = os.getenv("ALERT_EMAIL", smtp_user)

    if not smtp_user or not smtp_pass:
        log.warning("SMTP credentials not set — skipping email for alert #%s", alert['id'])
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[SIEM] {alert['severity']} Alert — {alert['title']}"
    msg["From"]    = f"SIEM Monitor <{smtp_user}>"
    msg["To"]      = to_email

    # Plain text fallback
    plain = (
        f"SIEM Alert — {alert['severity']}\n"
        f"Rule: {alert['rule_name']}\n"
        f"Title: {alert['title']}\n"
        f"IPs: {', '.join(alert['related_ips'] or [])}\n\n"
        f"AI Analysis:\n{alert['ai_explanation'] or 'Pending'}"
    )
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(build_html(alert), "html"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, to_email, msg.as_string())
        log.info("📧 Email sent for alert #%s to %s", alert['id'], to_email)
        return True
    except smtplib.SMTPException as e:
        log.error("SMTP error for alert #%s: %s", alert['id'], e)
        return False
    except Exception as e:
        log.error("Email error for alert #%s: %s", alert['id'], e)
        return False


# ── Main loop ─────────────────────────────────────────────────────────────

def run():
    ensure_email_column()
    log.info("Email notifier started. Watching for %s alerts every %ds.",
             NOTIFY_SEVERITIES, POLL_INTERVAL)

    while True:
        alerts = fetch_unsent_alerts()

        if alerts:
            log.info("Found %d unsent alert(s).", len(alerts))
            for alert in alerts:
                # Wait for AI explanation (up to 60s)
                waited = 0
                while not alert.get('ai_explanation') and waited < 60:
                    time.sleep(5)
                    waited += 5
                    # Re-fetch this specific alert to check for AI explanation
                    with get_conn() as conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                "SELECT ai_explanation FROM alerts WHERE id = %s",
                                (alert['id'],)
                            )
                            row = cur.fetchone()
                            if row and row[0]:
                                alert['ai_explanation'] = row[0]
                                break

                success = send_email(alert)
                if success:
                    mark_email_sent(alert['id'])
                time.sleep(2)
        else:
            log.debug("No unsent alerts found.")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
