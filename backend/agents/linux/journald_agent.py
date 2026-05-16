"""
journald_agent.py — Monitors systemd journal via journalctl for real-time events.

For modern Linux systems (Ubuntu 20+, Fedora, Arch) that use systemd.
Falls back gracefully if journalctl is not available.
"""
import json
import subprocess
import logging
from datetime import datetime, timezone

from agents.base import BaseAgent
import config

log = logging.getLogger("agent.journald")

# Priorities: 0=emerg 1=alert 2=crit 3=err 4=warn 5=notice 6=info 7=debug
PRIO_MAP = {
    "0": "CRITICAL", "1": "CRITICAL", "2": "CRITICAL",
    "3": "ERROR", "4": "WARNING", "5": "INFO",
    "6": "INFO", "7": "DEBUG",
}

# Systemd units that produce security-relevant events
SECURITY_UNITS = {"sshd", "sudo", "login", "systemd-logind", "su", "polkitd", "passwd"}


class JournaldAgent(BaseAgent):
    name = "journald_agent"
    source_name = "journald"
    os_type = "linux"

    def __init__(self):
        super().__init__()

    def collect(self):
        """Stream events from journalctl in JSON format."""
        cmd = [
            "journalctl",
            "-f",                   # follow (tail -f style)
            "-o", "json",           # JSON output
            "--no-pager",           # don't page
            "-p", "warning",        # priority ≤ warning (0-4)
        ]

        self.logger.info("Starting journalctl stream: %s", " ".join(cmd))

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )

            for line in proc.stdout:
                if not self._running:
                    proc.terminate()
                    break

                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                    event = self._parse_entry(entry)
                    if event:
                        self.emit_event(event)
                except json.JSONDecodeError:
                    continue

        except FileNotFoundError:
            self.logger.error("journalctl not found — JournaldAgent cannot start")
        except Exception as e:
            self.logger.error("JournaldAgent error: %s", e, exc_info=True)

    def _parse_entry(self, entry: dict) -> dict | None:
        """Parse a journalctl JSON entry into a NormalizedEvent dict."""
        message = entry.get("MESSAGE", "")
        if not message:
            return None

        # Filter for security-relevant units
        unit = entry.get("_SYSTEMD_UNIT", "").replace(".service", "")
        syslog_id = entry.get("SYSLOG_IDENTIFIER", "")

        priority = entry.get("PRIORITY", "6")
        severity = PRIO_MAP.get(str(priority), "INFO")

        # Parse timestamp (microseconds since epoch)
        ts_usec = entry.get("__REALTIME_TIMESTAMP", "")
        try:
            ts = datetime.fromtimestamp(int(ts_usec) / 1_000_000, tz=timezone.utc)
        except (ValueError, TypeError, OSError):
            ts = datetime.now(timezone.utc)

        # Determine event type
        event_type = "system_event"
        if syslog_id in ("sshd", "ssh"):
            event_type = "ssh_event"
        elif syslog_id == "sudo":
            event_type = "sudo_event"
        elif "kernel" in syslog_id.lower():
            event_type = "kernel_event"

        return {
            "source_name": self.source_name,
            "timestamp": ts,
            "severity": severity,
            "event_type": event_type,
            "message": f"[{syslog_id or unit}] {message[:200]}",
            "raw_log": str(entry.get("MESSAGE", "")),
            "host": entry.get("_HOSTNAME", config.HOSTNAME),
            "os_type": self.os_type,
            "extra_data": {
                "unit": unit,
                "syslog_identifier": syslog_id,
                "pid": entry.get("_PID", ""),
                "priority": priority,
            },
        }
