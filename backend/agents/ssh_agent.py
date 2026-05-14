"""
ssh_agent.py — Watches /var/log/auth.log for SSH events.

Detects:
  • Failed login attempts (wrong password / invalid user)
  • Successful logins
  • Brute-force: 5+ failures from same IP within 60 seconds → CRITICAL alert

Run:  python agents/ssh_agent.py
"""
import re
import time
import logging
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path

from models.db import insert_event, insert_alert

LOG_FILE   = Path("/var/log/auth.log")
TAIL_SLEEP = 1.0          # seconds between reads
BF_WINDOW  = 60           # brute-force detection window (seconds)
BF_THRESH  = 5            # failures within window = alert

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ssh_agent] %(levelname)s %(message)s"
)
log = logging.getLogger("ssh_agent")

# ------- regex patterns ------------------------------------------------
PATTERNS = {
    "failed_password": re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*"
        r"Failed password for (?:invalid user )?(?P<user>\S+) "
        r"from (?P<ip>[\d.]+)"
    ),
    "invalid_user": re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*"
        r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"
    ),
    "accepted_password": re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*"
        r"Accepted (?:password|publickey) for (?P<user>\S+) "
        r"from (?P<ip>[\d.]+)"
    ),
    "disconnected": re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*"
        r"Disconnected from (?:invalid user )?(?P<user>\S+)? *"
        r"(?:user )?from (?P<ip>[\d.]+)"
    ),
}

MONTH_MAP = {
    "Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
    "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12
}


def parse_timestamp(month_str, day_str, time_str):
    now = datetime.now()
    month = MONTH_MAP.get(month_str, now.month)
    day   = int(day_str)
    h, m, s = map(int, time_str.split(":"))
    return datetime(now.year, month, day, h, m, s, tzinfo=timezone.utc)


def parse_line(line: str):
    """Return (event_type, ts, ip, username, severity) or None."""
    for event_type, pattern in PATTERNS.items():
        m = pattern.search(line)
        if m:
            gd = m.groupdict()
            ts = parse_timestamp(gd["month"], gd["day"], gd["time"])
            ip   = gd.get("ip")
            user = gd.get("user") or "unknown"

            if event_type in ("failed_password", "invalid_user"):
                severity = "WARNING"
            elif event_type == "accepted_password":
                severity = "INFO"
            else:
                severity = "DEBUG"

            return event_type, ts, ip, user, severity
    return None


class BruteForceDetector:
    """Sliding-window counter per IP."""

    def __init__(self, window=BF_WINDOW, threshold=BF_THRESH):
        self.window    = window
        self.threshold = threshold
        # ip → list of failure timestamps
        self._failures: dict[str, list[float]] = defaultdict(list)
        self._alerted: set[str] = set()    # IPs already alerted (reset when cleared)

    def record_failure(self, ip: str, username: str, ts: datetime):
        now = ts.timestamp()
        self._failures[ip].append(now)
        # Keep only events within the window
        self._failures[ip] = [t for t in self._failures[ip] if now - t <= self.window]

        count = len(self._failures[ip])
        if count >= self.threshold and ip not in self._alerted:
            self._alerted.add(ip)
            self._trigger_alert(ip, username, count)

    def _trigger_alert(self, ip: str, username: str, count: int):
        log.warning("BRUTE FORCE DETECTED — IP %s (%d failures)", ip, count)
        title = f"SSH Brute Force Attack from {ip}"
        desc  = (
            f"{count} failed SSH login attempts in {self.window}s "
            f"targeting user '{username}'."
        )
        insert_alert(
            rule_name    = "ssh_brute_force",
            severity     = "CRITICAL",
            title        = title,
            description  = desc,
            related_ips  = [ip],
            related_users= [username],
            event_count  = count,
        )


def tail(filepath: Path):
    """Generator: yields new lines appended to a file (like `tail -f`)."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)          # jump to end of file
        log.info("Tailing %s …", filepath)
        while True:
            line = f.readline()
            if line:
                yield line.rstrip()
            else:
                time.sleep(TAIL_SLEEP)


def run():
    if not LOG_FILE.exists():
        log.error("Log file not found: %s  (are you running as root/sudo?)", LOG_FILE)
        return

    detector = BruteForceDetector()
    log.info("SSH agent started. Brute-force threshold: %d failures / %ds",
             BF_THRESH, BF_WINDOW)

    for line in tail(LOG_FILE):
        result = parse_line(line)
        if result is None:
            continue

        event_type, ts, ip, username, severity = result

        msg = f"SSH {event_type.replace('_',' ')} — user={username} ip={ip}"
        event_id = insert_event(
            source_name = "ssh",
            timestamp   = ts,
            severity    = severity,
            message     = msg,
            raw_log     = line,
            ip_address  = ip,
            username    = username,
            event_type  = event_type,
        )
        log.info("[event %s] %s", event_id, msg)

        if event_type in ("failed_password", "invalid_user"):
            detector.record_failure(ip, username, ts)


if __name__ == "__main__":
    run()
