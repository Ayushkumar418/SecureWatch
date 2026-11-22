"""Tests for normalizer/normalizer.py."""
from datetime import datetime, timezone

from normalizer.normalizer import (
    NormalizedEvent,
    create_event,
    normalize_severity,
    severity_for_windows_event,
)


def test_normalize_severity_mapping():
    assert normalize_severity("critical") == "CRITICAL"
    assert normalize_severity("crit") == "CRITICAL"
    assert normalize_severity("warn") == "WARNING"
    assert normalize_severity("err") == "ERROR"
    assert normalize_severity("INFO") == "INFO"
    assert normalize_severity("medium") == "MEDIUM"
    # Windows Event Viewer numeric levels
    assert normalize_severity("1") == "CRITICAL"
    assert normalize_severity("2") == "ERROR"
    assert normalize_severity("3") == "WARNING"
    assert normalize_severity("4") == "INFO"
    assert normalize_severity("5") == "DEBUG"
    # Unknown strings fall back to INFO, never crash
    assert normalize_severity("something-weird") == "INFO"
    assert normalize_severity("  error  ") == "ERROR"


def test_severity_for_windows_event():
    assert severity_for_windows_event(4625) == "WARNING"   # failed logon
    assert severity_for_windows_event(1116) == "CRITICAL"  # malware detected
    assert severity_for_windows_event(4732) == "CRITICAL"  # added to admin group
    assert severity_for_windows_event(7045) == "HIGH"      # service installed
    assert severity_for_windows_event(99999) == "INFO"     # unknown id
    assert severity_for_windows_event(99999, default="ERROR") == "ERROR"


def test_create_event_fills_defaults():
    ev = create_event("auth", "warning", "failed_password", "SSH failed login",
                      ip_address="1.2.3.4", username="root")
    assert isinstance(ev, NormalizedEvent)
    assert ev.severity == "WARNING"
    assert ev.source_name == "auth"
    assert ev.ip_address == "1.2.3.4"
    assert ev.username == "root"
    assert ev.extra_data == {}
    assert ev.timestamp.tzinfo is not None  # timezone-aware
    assert ev.host  # filled from config.HOSTNAME
    assert ev.os_type  # filled from config.OS_TYPE


def test_event_to_dict_serializes_timestamp():
    ts = datetime(2026, 11, 22, 12, 0, 0, tzinfo=timezone.utc)
    ev = create_event("apache", "info", "access", "GET /", timestamp=ts)
    d = ev.to_dict()
    assert d["timestamp"] == "2026-11-22T12:00:00+00:00"
    assert d["source_name"] == "apache"
    assert d["extra_data"] == {}
