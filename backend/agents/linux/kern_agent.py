"""
kern_agent.py — Monitors /var/log/kern.log for kernel-level events.

Detects:
  • Hardware faults
  • Kernel panics
  • Module load/unload (potential rootkit)
  • Firewall (iptables/nftables) deny events
  • USB device connections
"""
import re
import logging
from datetime import datetime, timezone
from pathlib import Path

from agents.base import BaseAgent
from agents.common.file_watcher import FileTailer
import config

log = logging.getLogger("agent.kern")

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

RULES = [
    ("kernel_panic", re.compile(r"Kernel panic", re.I),                  "CRITICAL", "kernel_panic"),
    ("oom_kill",     re.compile(r"Out of memory: Kill"),                  "ERROR",    "oom_kill"),
    ("hw_error",     re.compile(r"Hardware Error|Machine check", re.I),   "ERROR",    "hardware_error"),
    ("module_load",  re.compile(r"module.*loaded|insmod", re.I),          "WARNING",  "module_loaded"),
    ("fw_deny",      re.compile(r"iptables.*DROP|nftables.*drop|UFW BLOCK", re.I),  "WARNING",  "firewall_block"),
    ("usb_device",   re.compile(r"usb \d.*new.*device|USB disconnect"),   "INFO",     "usb_event"),
    ("segfault",     re.compile(r"segfault at"),                          "ERROR",    "segfault"),
]

HDR_RE = re.compile(r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)")


def _parse_timestamp(month_str, day_str, time_str):
    now = datetime.now()
    month = MONTH_MAP.get(month_str, now.month)
    return datetime(now.year, month, int(day_str),
                    *map(int, time_str.split(":")), tzinfo=timezone.utc)


class KernAgent(BaseAgent):
    name = "kern_agent"
    source_name = "kernel"
    os_type = "linux"

    def __init__(self, log_path=None):
        super().__init__()
        self.log_path = log_path or config.LINUX_LOG_PATHS["kern"]

    def collect(self):
        tailer = FileTailer(self.log_path, sleep_interval=config.TAIL_SLEEP)
        self.logger.info("Monitoring %s for kernel events", self.log_path)

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

        # Check against rules
        for rule_name, pattern, severity, event_type in RULES:
            if pattern.search(line):
                ip = None
                # Extract IP from firewall events
                fw_ip = re.search(r"SRC=([\d.]+)", line)
                if fw_ip:
                    ip = fw_ip.group(1)

                return {
                    "source_name": self.source_name,
                    "timestamp": ts,
                    "severity": severity,
                    "event_type": event_type,
                    "message": f"[kernel/{rule_name}] {line[20:200]}",
                    "raw_log": line,
                    "ip_address": ip,
                    "host": config.HOSTNAME,
                    "os_type": self.os_type,
                    "extra_data": {"rule_match": rule_name},
                }

        return None
