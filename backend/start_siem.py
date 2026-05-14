"""
start_siem.py — Starts ALL Phase 2 + Phase 3 services together.

Services started:
  1. Log simulator (generates fake attacks)
  2. Log collection agents (ssh, apache, syslog)
  3. AI analyzer      (Claude API — explains alerts)
  4. Email notifier   (sends email on HIGH/CRITICAL alerts)
  5. Flask API        (serves dashboard on port 5000)

Usage:
  python start_siem.py

Stop with Ctrl+C — all services shut down cleanly.
"""
import os
import sys
import time
import logging
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SIEM] %(levelname)s %(message)s"
)
log = logging.getLogger("SIEM")

BANNER = """
╔══════════════════════════════════════════════╗
║         SIEM PROJECT — Starting Up           ║
║  Phase 2: Log Collection + Detection         ║
║  Phase 3: AI Analysis + Email Alerts         ║
╚══════════════════════════════════════════════╝
"""


def start_thread(name: str, fn, daemon=True):
    def wrapper():
        try:
            fn()
        except Exception as e:
            log.error("[%s] crashed: %s", name, e, exc_info=True)

    t = threading.Thread(target=wrapper, name=name, daemon=daemon)
    t.start()
    log.info("  ✅ %-22s started (thread)", name)
    return t


def run_flask():
    """Run Flask API (blocking — runs in main thread last)."""
    import os
    os.environ.setdefault("FLASK_ENV", "production")
    from api.app import app
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)


def main():
    print(BANNER)

    # Check API key
    from dotenv import load_dotenv
    load_dotenv()
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key or "your-key" in api_key:
        log.warning("⚠️  ANTHROPIC_API_KEY not set — AI analysis will be skipped")
        ai_enabled = False
    else:
        ai_enabled = True

    # 1. Simulator (generates fake log attacks)
    from simulate_logs import run_simulator
    start_thread("log_simulator", run_simulator)
    time.sleep(1)   # let simulator create log files first

    # 2. Log agents (read logs → write to DB)
    from agents.ssh_agent    import run as run_ssh
    from agents.apache_agent import run as run_apache
    from agents.syslog_agent import run as run_syslog
    start_thread("ssh_agent",    run_ssh)
    start_thread("apache_agent", run_apache)
    start_thread("syslog_agent", run_syslog)
    time.sleep(1)

    # 3. AI analyzer (only if API key present)
    if ai_enabled:
        from ai_analyzer import run as run_ai
        start_thread("ai_analyzer", run_ai)

    # 4. Email notifier (only if SMTP configured)
    smtp_user = os.getenv("SMTP_USER", "")
    if smtp_user and "your_email" not in smtp_user:
        from email_notifier import run as run_email
        start_thread("email_notifier", run_email)
    else:
        log.warning("⚠️  SMTP not configured — email alerts disabled")

    time.sleep(1)

    log.info("")
    log.info("  🌐 Dashboard API: http://localhost:5000")
    log.info("  🌐 From Windows:  http://192.168.56.X:5000/api/stats")
    log.info("")
    log.info("  Endpoints:")
    log.info("    /api/health    — health check")
    log.info("    /api/stats     — dashboard summary")
    log.info("    /api/events    — all log events")
    log.info("    /api/alerts    — security alerts + AI explanations")
    log.info("")
    log.info("  Press Ctrl+C to stop all services.")
    log.info("")

    # 5. Flask API (blocking — runs last in main thread)
    try:
        run_flask()
    except KeyboardInterrupt:
        log.info("Shutting down SIEM...")


if __name__ == "__main__":
    main()
