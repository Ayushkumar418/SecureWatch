"""
config.py — Central configuration + automatic OS detection.

All settings are loaded from environment variables (.env file).
The OS is detected at import time and the correct log paths / agent
set is made available to the rest of the application.
"""
import os
import platform
from pathlib import Path
from dotenv import load_dotenv

# Load .env from backend/ directory
_backend_dir = Path(__file__).parent
load_dotenv(_backend_dir / ".env")

# ── OS Detection ──────────────────────────────────────────────────────────
OS_TYPE   = platform.system().lower()       # "windows" | "linux" | "darwin"
IS_WINDOWS = OS_TYPE == "windows"
IS_LINUX   = OS_TYPE == "linux"
IS_MAC     = OS_TYPE == "darwin"
HOSTNAME   = platform.node()
OS_VERSION = platform.version()
OS_RELEASE = platform.release()

# ── Database ──────────────────────────────────────────────────────────────
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", 5432))
DB_NAME = os.getenv("DB_NAME", "siem_db")
DB_USER = os.getenv("DB_USER", "siem_user")
DB_PASS = os.getenv("DB_PASSWORD", os.getenv("DB_PASS", "siem_pass"))

# ── Flask / API ───────────────────────────────────────────────────────────
API_PORT       = int(os.getenv("PORT", 5000))
API_HOST       = os.getenv("API_HOST", "0.0.0.0")
DASHBOARD_URL  = os.getenv("DASHBOARD_URL", "http://localhost:3000")
FLASK_ENV      = os.getenv("FLASK_ENV", "production")

# ── AI Keys ───────────────────────────────────────────────────────────────
GEMINI_API_KEY    = os.getenv("GEMINI_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

# ── Threat Intelligence (optional) ────────────────────────────────────────
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")

# ── Email ─────────────────────────────────────────────────────────────────
SMTP_HOST   = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT   = int(os.getenv("SMTP_PORT", 587))
SMTP_USER   = os.getenv("SMTP_USER", "")
SMTP_PASS   = os.getenv("SMTP_PASS", "")
ALERT_EMAIL = os.getenv("ALERT_EMAIL", SMTP_USER)

# ── Linux log paths ──────────────────────────────────────────────────────
LINUX_LOG_PATHS = {
    "auth":    Path("/var/log/auth.log"),
    "syslog":  Path("/var/log/syslog"),
    "kern":    Path("/var/log/kern.log"),
    "apache":  Path("/var/log/apache2/access.log"),
    "nginx":   Path("/var/log/nginx/access.log"),
}

# ── Windows Event Log channels ───────────────────────────────────────────
WINDOWS_CHANNELS = {
    "security":    "Security",
    "system":      "System",
    "application": "Application",
    "defender":    "Microsoft-Windows-Windows Defender/Operational",
    "powershell":  "Microsoft-Windows-PowerShell/Operational",
}

# ── Simulation (demo mode) ───────────────────────────────────────────────
SIM_DIR = Path(os.getenv("SIM_LOG_DIR", "/tmp/siem_sim_logs"))
DEMO_MODE = os.getenv("SIEM_DEMO_MODE", "false").lower() == "true"

# ── Agent settings ────────────────────────────────────────────────────────
TAIL_SLEEP       = float(os.getenv("TAIL_SLEEP", 0.5))
POLL_INTERVAL_AI = int(os.getenv("AI_POLL_INTERVAL", 30))
POLL_INTERVAL_EMAIL = int(os.getenv("EMAIL_POLL_INTERVAL", 60))

# ── Detection thresholds ─────────────────────────────────────────────────
BF_WINDOW    = int(os.getenv("BF_WINDOW", 120))      # brute-force window (seconds)
BF_THRESHOLD = int(os.getenv("BF_THRESHOLD", 5))      # failures in window = alert
SCAN_WINDOW  = int(os.getenv("SCAN_WINDOW", 30))      # HTTP scan window
SCAN_THRESHOLD = int(os.getenv("SCAN_THRESHOLD", 20))  # 4xx count in window


def print_config_summary():
    """Print startup summary of detected configuration."""
    gemini  = "[OK]" if GEMINI_API_KEY and "your" not in GEMINI_API_KEY else "[--]"
    anthro  = "[OK]" if ANTHROPIC_API_KEY and "your" not in ANTHROPIC_API_KEY else "[--]"
    vt      = "[OK]" if VIRUSTOTAL_API_KEY else "[--]"
    abuse   = "[OK]" if ABUSEIPDB_API_KEY else "[--]"
    email   = "[OK]" if SMTP_USER and "your" not in SMTP_USER else "[--]"
    mode    = "DEMO (simulated logs)" if DEMO_MODE else "LIVE (real system logs)"

    lines = [
        "+----------------------------------------------------------+",
        "|           SecureWatch AI - Configuration                  |",
        "+----------------------------------------------------------+",
        f"|  OS:          {OS_TYPE} ({OS_RELEASE})",
        f"|  Hostname:    {HOSTNAME}",
        f"|  Mode:        {mode}",
        f"|  Database:    {DB_HOST}:{DB_PORT}/{DB_NAME}",
        f"|  API:         {API_HOST}:{API_PORT}",
        f"|  Gemini AI:   {gemini}",
        f"|  Anthropic:   {anthro}",
        f"|  VirusTotal:  {vt}",
        f"|  AbuseIPDB:   {abuse}",
        f"|  Email:       {email}",
        "+----------------------------------------------------------+",
    ]
    print("\n".join(lines))
