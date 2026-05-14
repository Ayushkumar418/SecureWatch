"""
apache_agent.py — Watches Apache2 access.log for suspicious HTTP activity.

Detects:
  • High rate of 4xx errors from a single IP  → port/path scanning
  • SQL injection patterns in URLs            → attack attempt
  • Requests to sensitive paths (/admin, /.env, /wp-login.php …)

Run:  python agents/apache_agent.py
"""
import re
import time
import logging
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path

from models.db import insert_event, insert_alert

LOG_FILE        = Path("/var/log/apache2/access.log")
TAIL_SLEEP      = 1.0
SCAN_WINDOW     = 30     # seconds
SCAN_THRESH_4XX = 20     # 4xx errors from same IP in window = scanner alert

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [apache_agent] %(levelname)s %(message)s"
)
log = logging.getLogger("apache_agent")

# Combined Log Format:
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "ref" "ua"
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
    r"/shell|/config|/backup|/\.htaccess|/xmlrpc\.php)",
    re.IGNORECASE
)

SQLI_PATTERN = re.compile(
    r"(union\s+select|drop\s+table|insert\s+into|or\s+1=1|"
    r"'--|\bxp_cmdshell\b|benchmark\(|sleep\()",
    re.IGNORECASE
)


def parse_line(line: str):
    m = ACCESS_RE.match(line)
    if not m:
        return None
    gd     = m.groupdict()
    try:
        ts = datetime.strptime(gd["time"], TIME_FMT).astimezone(timezone.utc)
    except ValueError:
        ts = datetime.now(timezone.utc)

    status = int(gd["status"])
    path   = gd["path"]
    ip     = gd["ip"]
    method = gd["method"]

    # Classify severity
    if SQLI_PATTERN.search(path):
        severity   = "CRITICAL"
        event_type = "sqli_attempt"
    elif SENSITIVE_PATHS.search(path):
        severity   = "HIGH"
        event_type = "sensitive_path"
    elif 500 <= status < 600:
        severity   = "ERROR"
        event_type = "server_error"
    elif 400 <= status < 500:
        severity   = "WARNING"
        event_type = "client_error"
    else:
        severity   = "INFO"
        event_type = "access"

    return {
        "ts": ts, "ip": ip, "method": method, "path": path,
        "status": status, "severity": severity, "event_type": event_type,
        "ua": gd.get("ua", ""),
    }


class ScanDetector:
    """Count 4xx responses per IP in a sliding window."""

    def __init__(self, window=SCAN_WINDOW, threshold=SCAN_THRESH_4XX):
        self.window    = window
        self.threshold = threshold
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._alerted: set[str] = set()

    def record(self, ip: str, ts: datetime, status: int):
        if not (400 <= status < 500):
            return
        now = ts.timestamp()
        self._hits[ip].append(now)
        self._hits[ip] = [t for t in self._hits[ip] if now - t <= self.window]

        count = len(self._hits[ip])
        if count >= self.threshold and ip not in self._alerted:
            self._alerted.add(ip)
            log.warning("SCANNER DETECTED — IP %s (%d x 4xx in %ds)", ip, count, self.window)
            insert_alert(
                rule_name   = "http_scan",
                severity    = "HIGH",
                title       = f"HTTP Scanning from {ip}",
                description = (
                    f"{count} HTTP 4xx errors from {ip} in {self.window}s. "
                    "Possible path/vulnerability scanner."
                ),
                related_ips = [ip],
                event_count = count,
            )


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

    scanner = ScanDetector()
    log.info("Apache agent started.")

    for line in tail(LOG_FILE):
        parsed = parse_line(line)
        if parsed is None:
            continue

        msg = (
            f"{parsed['method']} {parsed['path']} → {parsed['status']} "
            f"[{parsed['event_type']}] ip={parsed['ip']}"
        )
        event_id = insert_event(
            source_name = "apache",
            timestamp   = parsed["ts"],
            severity    = parsed["severity"],
            message     = msg,
            raw_log     = line,
            ip_address  = parsed["ip"],
            event_type  = parsed["event_type"],
            extra_data  = {
                "method": parsed["method"],
                "path":   parsed["path"],
                "status": parsed["status"],
                "ua":     parsed["ua"],
            },
        )
        log.info("[event %s] %s", event_id, msg)

        # Sqli / sensitive path → immediate alert
        if parsed["event_type"] == "sqli_attempt":
            insert_alert(
                rule_name   = "sqli_attempt",
                severity    = "CRITICAL",
                title       = f"SQL Injection Attempt from {parsed['ip']}",
                description = f"Suspicious payload in path: {parsed['path'][:200]}",
                related_ips = [parsed["ip"]],
            )

        scanner.record(parsed["ip"], parsed["ts"], parsed["status"])


if __name__ == "__main__":
    run()
