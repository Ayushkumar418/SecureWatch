"""
correlator.py — Multi-event correlation engine.

Detects attack patterns that span multiple events within a time window:
  - SSH/RDP brute force (N failed logins from same IP in X seconds)
  - HTTP scanning (N 4xx errors from same IP in X seconds)
  - Account lockout storms
  - Authentication anomalies
"""
import time
import logging
from collections import defaultdict

import config

log = logging.getLogger("detection.correlator")


class SlidingWindowCounter:
    """Counts events per key within a sliding time window."""

    def __init__(self, window_seconds: int):
        self.window = window_seconds
        self._buckets: dict[str, list[float]] = defaultdict(list)

    def record(self, key: str, timestamp: float = None) -> int:
        """Record an event for `key`. Returns count within window."""
        now = timestamp or time.time()
        self._buckets[key].append(now)
        # Prune old entries
        self._buckets[key] = [
            t for t in self._buckets[key] if now - t <= self.window
        ]
        return len(self._buckets[key])

    def reset(self, key: str):
        """Reset the counter for a key (after alert fires)."""
        self._buckets.pop(key, None)


class EventCorrelator:
    """
    Processes events and detects time-window-based attack patterns.
    Returns a list of alert dicts when patterns are detected.
    """

    def __init__(self):
        # Brute force: failed logins per IP
        self._bf_counter = SlidingWindowCounter(config.BF_WINDOW)
        self._bf_alerted: set[str] = set()

        # HTTP scanning: 4xx errors per IP
        self._scan_counter = SlidingWindowCounter(config.SCAN_WINDOW)
        self._scan_alerted: set[str] = set()

        # Windows failed logon: per IP
        self._win_bf_counter = SlidingWindowCounter(config.BF_WINDOW)
        self._win_bf_alerted: set[str] = set()

        # Account lockout: per username
        self._lockout_counter = SlidingWindowCounter(300)  # 5 min window
        self._lockout_alerted: set[str] = set()

    def process(self, event: dict) -> list[dict]:
        """
        Process an event and return any triggered correlation alerts.
        Returns an empty list if no correlations fire.
        """
        alerts = []
        event_type = event.get("event_type", "")
        source = event.get("source_name", "")
        ip = event.get("ip_address", "")
        username = event.get("username", "")

        # ── SSH / Linux brute force ───────────────────────────────────
        if event_type in ("failed_password", "invalid_user") and ip:
            count = self._bf_counter.record(ip)
            if count >= config.BF_THRESHOLD and ip not in self._bf_alerted:
                self._bf_alerted.add(ip)
                alerts.append({
                    "rule_name": "ssh_brute_force",
                    "severity": "CRITICAL",
                    "title": f"SSH Brute Force Attack from {ip}",
                    "description": (
                        f"{count} failed SSH login attempts from {ip} "
                        f"within {config.BF_WINDOW}s. Target user: '{username}'."
                    ),
                    "related_ips": [ip],
                    "related_users": [username] if username else [],
                    "event_count": count,
                })
                log.warning("SSH BRUTE FORCE: %s (%d failures)", ip, count)

        # ── HTTP scanning ─────────────────────────────────────────────
        if source in ("apache", "nginx"):
            status = event.get("extra_data", {}).get("status", 0)
            if isinstance(status, int) and 400 <= status < 500 and ip:
                count = self._scan_counter.record(ip)
                if count >= config.SCAN_THRESHOLD and ip not in self._scan_alerted:
                    self._scan_alerted.add(ip)
                    alerts.append({
                        "rule_name": "http_scan",
                        "severity": "HIGH",
                        "title": f"HTTP Scanning from {ip}",
                        "description": (
                            f"{count} HTTP 4xx errors from {ip} "
                            f"within {config.SCAN_WINDOW}s. Likely vulnerability scanner."
                        ),
                        "related_ips": [ip],
                        "event_count": count,
                    })

        # ── Windows failed logon (Event ID 4625) ─────────────────────
        if event.get("extra_data", {}).get("event_id") == 4625 and ip:
            count = self._win_bf_counter.record(ip)
            if count >= config.BF_THRESHOLD and ip not in self._win_bf_alerted:
                self._win_bf_alerted.add(ip)
                logon_type = event.get("extra_data", {}).get("logon_type", "")
                attack_type = "RDP" if logon_type == "10" else "Windows"
                alerts.append({
                    "rule_name": f"{attack_type.lower()}_brute_force",
                    "severity": "CRITICAL",
                    "title": f"{attack_type} Brute Force Attack from {ip}",
                    "description": (
                        f"{count} failed {attack_type} login attempts from {ip} "
                        f"within {config.BF_WINDOW}s."
                    ),
                    "related_ips": [ip],
                    "related_users": [username] if username else [],
                    "event_count": count,
                })

        # ── Account lockout storm (Event ID 4740) ────────────────────
        if event.get("extra_data", {}).get("event_id") == 4740 and username:
            count = self._lockout_counter.record(username)
            if count >= 3 and username not in self._lockout_alerted:
                self._lockout_alerted.add(username)
                alerts.append({
                    "rule_name": "account_lockout_storm",
                    "severity": "HIGH",
                    "title": f"Account Lockout Storm: {username}",
                    "description": (
                        f"Account '{username}' has been locked out {count} times "
                        f"within 5 minutes. Possible brute force attack."
                    ),
                    "related_users": [username],
                    "event_count": count,
                })

        return alerts
