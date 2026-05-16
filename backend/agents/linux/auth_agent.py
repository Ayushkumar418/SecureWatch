"""
auth_agent.py — Monitors /var/log/auth.log for SSH and authentication events.

Detects:
  • Failed SSH login attempts (wrong password / invalid user)
  • Successful SSH logins
  • sudo command usage
  • su (switch user) events

Brute-force correlation is handled by the central DetectionEngine/Correlator,
not by this agent directly.
"""
import re
import logging
from datetime import datetime, timezone
from pathlib import Path

from agents.base import BaseAgent
from agents.common.file_watcher import FileTailer
import config

log = logging.getLogger("agent.auth")


# ── Regex patterns for auth.log ──────────────────────────────────────────

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
    "sudo_command": re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*"
        r"(?P<user>\S+)\s*:\s*TTY=\S+\s*;\s*.*COMMAND=(?P<cmd>.+)"
    ),
    "su_switch": re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*"
        r"su.*session opened for user (?P<user>\S+)"
    ),
}

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

SEVERITY_MAP = {
    "failed_password":   "WARNING",
    "invalid_user":      "WARNING",
    "accepted_password": "INFO",
    "sudo_command":      "WARNING",
    "su_switch":         "INFO",
}


def _parse_timestamp(month_str, day_str, time_str):
    now = datetime.now()
    month = MONTH_MAP.get(month_str, now.month)
    day = int(day_str)
    h, m, s = map(int, time_str.split(":"))
    return datetime(now.year, month, day, h, m, s, tzinfo=timezone.utc)


class AuthAgent(BaseAgent):
    name = "auth_agent"
    source_name = "auth"
    os_type = "linux"

    def __init__(self, log_path=None):
        super().__init__()
        self.log_path = log_path or config.LINUX_LOG_PATHS["auth"]

    def collect(self):
        tailer = FileTailer(self.log_path, sleep_interval=config.TAIL_SLEEP)
        self.logger.info("Monitoring %s for SSH/auth events", self.log_path)

        for line in tailer.follow():
            if not self._running:
                break
            event = self._parse_line(line)
            if event:
                self.emit_event(event)

    def _parse_line(self, line: str) -> dict | None:
        for event_type, pattern in PATTERNS.items():
            m = pattern.search(line)
            if not m:
                continue
            gd = m.groupdict()

            try:
                ts = _parse_timestamp(gd.get("month", ""), gd.get("day", ""), gd.get("time", ""))
            except (ValueError, KeyError):
                ts = datetime.now(timezone.utc)

            ip = gd.get("ip")
            user = gd.get("user", "unknown")
            severity = SEVERITY_MAP.get(event_type, "INFO")

            # Root login → escalate severity
            if event_type == "accepted_password" and user == "root":
                severity = "CRITICAL"

            msg = f"SSH {event_type.replace('_', ' ')} — user={user}"
            if ip:
                msg += f" ip={ip}"
            if event_type == "sudo_command":
                msg = f"sudo by {user}: {gd.get('cmd', '')[:100]}"

            return {
                "source_name": self.source_name,
                "timestamp": ts,
                "severity": severity,
                "event_type": event_type,
                "message": msg,
                "raw_log": line,
                "ip_address": ip,
                "username": user,
                "host": config.HOSTNAME,
                "os_type": self.os_type,
                "extra_data": {k: v for k, v in gd.items() if k not in ("month", "day", "time")},
            }

        return None
