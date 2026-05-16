"""
syslog_agent.py — Monitors /var/log/syslog for system-level events.

Detects:
  • New user/group creation (persistence)
  • OOM kills (resource exhaustion)
  • Kernel errors
  • Cron job execution
  • Root login via console
  • Password changes
"""
import re
import logging
from datetime import datetime, timezone
from pathlib import Path

from agents.base import BaseAgent
from agents.common.file_watcher import FileTailer
import config

log = logging.getLogger("agent.syslog")

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

RULES = [
    ("new_user",       re.compile(r"(\w+)\s+(\d+)\s+([\d:]+).*useradd.*new user: name=(?P<user>\S+)"),        "CRITICAL", "user_created"),
    ("new_group",      re.compile(r"(\w+)\s+(\d+)\s+([\d:]+).*groupadd.*new group: name=(?P<grp>\S+)"),       "WARNING",  "group_created"),
    ("oom_kill",       re.compile(r"(\w+)\s+(\d+)\s+([\d:]+).*Out of memory: Kill process (?P<pid>\d+) \((?P<proc>\S+)\)"), "ERROR", "oom_kill"),
    ("kernel_error",   re.compile(r"(\w+)\s+(\d+)\s+([\d:]+).*kernel:.*(?:error|fault|oops|panic)", re.I),    "ERROR",    "kernel_error"),
    ("cron_exec",      re.compile(r"(\w+)\s+(\d+)\s+([\d:]+).*CRON.*CMD\s*\((?P<cmd>.+)\)"),                  "INFO",     "cron_job"),
    ("ssh_rootlogin",  re.compile(r"(\w+)\s+(\d+)\s+([\d:]+).*sshd.*ROOT LOGIN on"),                          "CRITICAL", "root_login"),
    ("passwd_change",  re.compile(r"(\w+)\s+(\d+)\s+([\d:]+).*passwd.*password changed for (?P<user>\S+)"),    "WARNING",  "password_changed"),
    ("sudo_exec",     re.compile(r"(\w+)\s+(\d+)\s+([\d:]+).*sudo.*COMMAND=(?P<cmd>.+)"),                     "WARNING",  "sudo_execution"),
]

HDR_RE = re.compile(r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)")


def _parse_timestamp(month_str, day_str, time_str):
    now = datetime.now()
    month = MONTH_MAP.get(month_str, now.month)
    day = int(day_str)
    h, m, s = map(int, time_str.split(":"))
    return datetime(now.year, month, day, h, m, s, tzinfo=timezone.utc)


class SyslogAgent(BaseAgent):
    name = "syslog_agent"
    source_name = "syslog"
    os_type = "linux"

    def __init__(self, log_path=None):
        super().__init__()
        self.log_path = log_path or config.LINUX_LOG_PATHS["syslog"]

    def collect(self):
        tailer = FileTailer(self.log_path, sleep_interval=config.TAIL_SLEEP)
        self.logger.info("Monitoring %s for system events", self.log_path)

        for line in tailer.follow():
            if not self._running:
                break
            event = self._parse_line(line)
            if event:
                self.emit_event(event)

    def _parse_line(self, line: str) -> dict | None:
        hdr = HDR_RE.match(line)
        if not hdr:
            return None

        try:
            ts = _parse_timestamp(hdr["month"], hdr["day"], hdr["time"])
        except (ValueError, KeyError):
            ts = datetime.now(timezone.utc)

        for rule_name, pattern, severity, event_type in RULES:
            m = pattern.search(line)
            if not m:
                continue

            gd = m.groupdict()
            msg = f"[{rule_name}] {line[20:150]}"

            return {
                "source_name": self.source_name,
                "timestamp": ts,
                "severity": severity,
                "event_type": event_type,
                "message": msg,
                "raw_log": line,
                "username": gd.get("user"),
                "host": config.HOSTNAME,
                "os_type": self.os_type,
                "extra_data": gd,
            }

        return None
