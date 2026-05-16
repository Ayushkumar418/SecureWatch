"""
apache_agent.py — Monitors Apache/Nginx access logs for HTTP threats.

Detects:
  • SQL injection patterns in URLs
  • Requests to sensitive paths (.env, .git, /admin, etc.)
  • High rate of 4xx errors (scanning)
  • Server errors (5xx)

Correlation-based detection (scan threshold) is handled by the DetectionEngine.
"""
import re
import logging
from datetime import datetime, timezone
from pathlib import Path

from agents.base import BaseAgent
from agents.common.file_watcher import FileTailer
import config

log = logging.getLogger("agent.apache")

# Combined Log Format regex
ACCESS_RE = re.compile(
    r'(?P<ip>[\d.]+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)")?'
    r'(?:\s+"(?P<ua>[^"]*)")?'
)

TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

SENSITIVE_PATHS = re.compile(
    r"(\.env|\.git|/admin|/wp-login|/phpmyadmin|/etc/passwd|"
    r"/shell|/config|/backup|/\.htaccess|/xmlrpc\.php|"
    r"/\.aws|/\.ssh|/wp-config\.php|/server-status)",
    re.IGNORECASE,
)

SQLI_PATTERN = re.compile(
    r"(union\s+select|drop\s+table|insert\s+into|or\s+1=1|"
    r"'--|xp_cmdshell|benchmark\(|sleep\(|load_file)",
    re.IGNORECASE,
)


class ApacheAgent(BaseAgent):
    name = "apache_agent"
    source_name = "apache"
    os_type = "linux"

    def __init__(self, log_path=None):
        super().__init__()
        # Auto-detect Apache vs Nginx
        if log_path:
            self.log_path = Path(log_path)
        elif config.LINUX_LOG_PATHS["apache"].exists():
            self.log_path = config.LINUX_LOG_PATHS["apache"]
        elif config.LINUX_LOG_PATHS["nginx"].exists():
            self.log_path = config.LINUX_LOG_PATHS["nginx"]
            self.source_name = "nginx"
        else:
            self.log_path = config.LINUX_LOG_PATHS["apache"]

    def collect(self):
        tailer = FileTailer(self.log_path, sleep_interval=config.TAIL_SLEEP)
        self.logger.info("Monitoring %s for HTTP activity", self.log_path)

        for line in tailer.follow():
            if not self._running:
                break
            event = self._parse_line(line)
            if event:
                self.emit_event(event)

    def _parse_line(self, line: str) -> dict | None:
        m = ACCESS_RE.match(line)
        if not m:
            return None

        gd = m.groupdict()
        try:
            ts = datetime.strptime(gd["time"], TIME_FMT).astimezone(timezone.utc)
        except ValueError:
            ts = datetime.now(timezone.utc)

        status = int(gd["status"])
        path = gd["path"]
        ip = gd["ip"]
        method = gd["method"]

        # Classify
        if SQLI_PATTERN.search(path):
            severity, event_type = "CRITICAL", "sqli_attempt"
        elif SENSITIVE_PATHS.search(path):
            severity, event_type = "HIGH", "sensitive_path"
        elif 500 <= status < 600:
            severity, event_type = "ERROR", "server_error"
        elif 400 <= status < 500:
            severity, event_type = "WARNING", "client_error"
        else:
            severity, event_type = "INFO", "access"

        msg = f"{method} {path} → {status} [{event_type}] ip={ip}"

        return {
            "source_name": self.source_name,
            "timestamp": ts,
            "severity": severity,
            "event_type": event_type,
            "message": msg,
            "raw_log": line,
            "ip_address": ip,
            "host": config.HOSTNAME,
            "os_type": self.os_type,
            "extra_data": {
                "method": method,
                "path": path,
                "status": status,
                "ua": gd.get("ua", ""),
            },
        }
