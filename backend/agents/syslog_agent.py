"""
syslog_agent.py — Watches /var/log/syslog for system-level threats.

Detects:
  • Sudo command executions (privilege escalation)
  • OOM (out-of-memory) kills
  • Kernel errors / hardware faults
  • Cron job activity
  • New user/group creation (persistence indicators)

Run:  python agents/syslog_agent.py
"""
import re
import time
import logging
from datetime import datetime, timezone
from pathlib import Path

from models.db import insert_event, insert_alert

LOG_FILE   = Path("/var/log/syslog")
TAIL_SLEEP = 1.0

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [syslog_agent] %(levelname)s %(message)s"
)
log = logging.getLogger("syslog_agent")

MONTH_MAP = {
    "Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
    "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12
}

# Each rule: (name, regex, severity, event_type, alert_severity|None)
RULES = [
    (
        "sudo_exec",
        re.compile(r"(\w+)\s+(\d+)\s+([\d:]+).*sudo.*COMMAND=(?P<cmd>.+)"),
        "WARNING", "sudo_execution", None,   # no alert unless you want one
    ),
    (
        "new_user",
        re.compile(r"(\w+)\s+(\d+)\s+([\d:]+).*useradd.*new user: name=(?P<user>\S+)"),
        "CRITICAL", "user_created", "HIGH",
    ),
    (
        "new_group",
        re.compile(r"(\w+)\s+(\d+)\s+([\d:]+).*groupadd.*new group: name=(?P<grp>\S+)"),
        "WARNING", "group_created", None,
    ),
    (
        "oom_kill",
        re.compile(r"(\w+)\s+(\d+)\s+([\d:]+).*Out of memory: Kill process (?P<pid>\d+) \((?P<proc>\S+)\)"),
        "ERROR", "oom_kill", "MEDIUM",
    ),
    (
        "kernel_error",
        re.compile(r"(\w+)\s+(\d+)\s+([\d:]+).*kernel:.*(?:error|fault|oops|panic)", re.IGNORECASE),
        "ERROR", "kernel_error", "HIGH",
    ),
    (
        "cron_exec",
        re.compile(r"(\w+)\s+(\d+)\s+([\d:]+).*CRON.*CMD\s*\((?P<cmd>.+)\)"),
        "INFO", "cron_job", None,
    ),
    (
        "ssh_rootlogin",
        re.compile(r"(\w+)\s+(\d+)\s+([\d:]+).*sshd.*ROOT LOGIN on"),
        "CRITICAL", "root_login", "CRITICAL",
    ),
    (
        "passwd_change",
        re.compile(r"(\w+)\s+(\d+)\s+([\d:]+).*passwd.*password changed for (?P<user>\S+)"),
        "WARNING", "password_changed", "MEDIUM",
    ),
]

# Generic header parser
HDR_RE = re.compile(r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)")


def parse_timestamp(month_str, day_str, time_str):
    now   = datetime.now()
    month = MONTH_MAP.get(month_str, now.month)
    day   = int(day_str)
    h, m, s = map(int, time_str.split(":"))
    return datetime(now.year, month, day, h, m, s, tzinfo=timezone.utc)


def process_line(line: str):
    hdr = HDR_RE.match(line)
    if not hdr:
        return

    ts = parse_timestamp(hdr["month"], hdr["day"], hdr["time"])

    for rule_name, pattern, severity, event_type, alert_sev in RULES:
        m = pattern.search(line)
        if not m:
            continue

        gd  = m.groupdict()
        msg = f"[{rule_name}] {line[20:120]}"   # trim header, cap length

        event_id = insert_event(
            source_name = "syslog",
            timestamp   = ts,
            severity    = severity,
            message     = msg,
            raw_log     = line,
            event_type  = event_type,
            extra_data  = gd,
        )
        log.info("[event %s] %s | %s", event_id, event_type, msg[:80])

        # Fire alert if rule has an alert severity
        if alert_sev:
            insert_alert(
                rule_name   = rule_name,
                severity    = alert_sev,
                title       = f"System event: {event_type.replace('_',' ').title()}",
                description = msg,
            )
        break   # match only first rule per line


def tail(filepath: Path):
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)
        log.info("Tailing %s …", filepath)
        while True:
            line = f.readline()
            if line:
                yield line.rstrip()
            else:
                time.sleep(TAIL_SLEEP)


def run():
    if not LOG_FILE.exists():
        log.error("Log file not found: %s", LOG_FILE)
        return

    log.info("Syslog agent started. Watching for %d rule types.", len(RULES))

    for line in tail(LOG_FILE):
        process_line(line)


if __name__ == "__main__":
    run()
