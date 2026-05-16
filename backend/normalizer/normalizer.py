"""
normalizer.py — Unified log normalization layer.

Converts raw log events from any OS/source into a standard schema that
the detection engine, DB, and dashboard all understand.
"""
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional

import config


@dataclass
class NormalizedEvent:
    """Standard event schema — all agents must produce this."""
    timestamp: datetime
    host: str
    os_type: str               # "windows" | "linux"
    source_name: str           # "auth", "security", "apache", "defender", etc.
    severity: str              # CRITICAL | HIGH | ERROR | WARNING | INFO | DEBUG
    event_type: str            # "failed_login", "brute_force", "malware_detected", etc.
    message: str               # human-readable summary
    ip_address: Optional[str] = None
    username: Optional[str] = None
    raw_log: Optional[str] = None
    extra_data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dict for DB insertion and WebSocket emission."""
        d = asdict(self)
        # Ensure timestamp is ISO format string for JSON
        if isinstance(d["timestamp"], datetime):
            d["timestamp"] = d["timestamp"].isoformat()
        return d


# ── Severity mapping helpers ──────────────────────────────────────────────

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH":     4,
    "ERROR":    3,
    "WARNING":  2,
    "MEDIUM":   2,
    "INFO":     1,
    "LOW":      1,
    "DEBUG":    0,
}


def normalize_severity(raw_severity: str) -> str:
    """Map various severity strings to our standard set."""
    mapping = {
        # Standard
        "critical": "CRITICAL", "crit": "CRITICAL",
        "high": "HIGH",
        "error": "ERROR", "err": "ERROR",
        "warning": "WARNING", "warn": "WARNING",
        "medium": "MEDIUM",
        "info": "INFO", "information": "INFO", "informational": "INFO",
        "low": "LOW",
        "debug": "DEBUG", "verbose": "DEBUG",
        # Windows Event Viewer levels
        "1": "CRITICAL",    # Critical
        "2": "ERROR",       # Error
        "3": "WARNING",     # Warning
        "4": "INFO",        # Information
        "5": "DEBUG",       # Verbose
        "0": "INFO",        # LogAlways
    }
    return mapping.get(raw_severity.lower().strip(), "INFO")


# ── Windows Event ID severity mapping ────────────────────────────────────

WINDOWS_SEVERITY_MAP = {
    # Security
    4625: "WARNING",    # Failed logon
    4624: "INFO",       # Successful logon
    4648: "WARNING",    # Logon using explicit credentials
    4720: "HIGH",       # User account created
    4722: "WARNING",    # User account enabled
    4732: "CRITICAL",   # Member added to security-enabled group
    4740: "HIGH",       # Account locked out
    4672: "WARNING",    # Special privileges assigned
    4688: "INFO",       # New process created
    4697: "HIGH",       # Service installed
    # System
    7045: "HIGH",       # Service installed
    1074: "INFO",       # System shutdown/restart
    41:   "WARNING",    # Unexpected shutdown
    6005: "INFO",       # Event Log service started
    6006: "WARNING",    # Event Log service stopped
    # Defender
    1116: "CRITICAL",   # Malware detected
    1117: "HIGH",       # Action taken on malware
    5001: "CRITICAL",   # Real-time protection disabled
    5010: "HIGH",       # Scanning disabled
}


def severity_for_windows_event(event_id: int, default: str = "INFO") -> str:
    """Get severity for a Windows Event ID."""
    return WINDOWS_SEVERITY_MAP.get(event_id, default)


# ── Factory function ─────────────────────────────────────────────────────

def create_event(
    source_name: str,
    severity: str,
    event_type: str,
    message: str,
    timestamp: datetime = None,
    ip_address: str = None,
    username: str = None,
    raw_log: str = None,
    extra_data: dict = None,
) -> NormalizedEvent:
    """
    Convenience factory to create a NormalizedEvent with auto-filled defaults.
    """
    return NormalizedEvent(
        timestamp=timestamp or datetime.now(timezone.utc),
        host=config.HOSTNAME,
        os_type=config.OS_TYPE,
        source_name=source_name,
        severity=normalize_severity(severity),
        event_type=event_type,
        message=message,
        ip_address=ip_address,
        username=username,
        raw_log=raw_log,
        extra_data=extra_data or {},
    )
