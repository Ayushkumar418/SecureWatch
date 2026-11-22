"""Tests for detection/correlator.py — multi-event correlation."""
import time

import config
from detection.correlator import EventCorrelator, SlidingWindowCounter


def _failed_ssh(ip, user="root"):
    return {"event_type": "failed_password", "source_name": "auth",
            "ip_address": ip, "username": user}


def _http_4xx(ip, status=404):
    return {"event_type": "access", "source_name": "apache",
            "ip_address": ip, "extra_data": {"status": status}}


def test_ssh_brute_force_fires_at_threshold():
    corr = EventCorrelator()
    alerts = []
    for _ in range(config.BF_THRESHOLD - 1):
        alerts += corr.process(_failed_ssh("10.0.0.1"))
    assert alerts == []
    alerts += corr.process(_failed_ssh("10.0.0.1"))
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "ssh_brute_force"
    assert alerts[0]["severity"] == "CRITICAL"
    assert alerts[0]["related_ips"] == ["10.0.0.1"]


def test_ssh_brute_force_does_not_realert_same_ip():
    corr = EventCorrelator()
    total = []
    for _ in range(config.BF_THRESHOLD + 3):
        total += corr.process(_failed_ssh("10.0.0.2"))
    assert len(total) == 1  # fires once per IP until process restart


def test_ssh_brute_force_is_per_ip():
    corr = EventCorrelator()
    for _ in range(config.BF_THRESHOLD):
        corr.process(_failed_ssh("10.0.0.3"))
    # A different IP with one failure must not alert.
    assert corr.process(_failed_ssh("10.0.0.4")) == []


def test_http_scan_fires_at_threshold():
    corr = EventCorrelator()
    alerts = []
    for _ in range(config.SCAN_THRESHOLD):
        alerts += corr.process(_http_4xx("10.0.0.5"))
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "http_scan"


def test_http_scan_ignores_success_status():
    corr = EventCorrelator()
    alerts = []
    for _ in range(config.SCAN_THRESHOLD + 5):
        alerts += corr.process(_http_4xx("10.0.0.6", status=200))
    assert alerts == []


def test_account_lockout_storm():
    corr = EventCorrelator()
    ev = {"event_type": "account_locked", "source_name": "security",
          "ip_address": "10.0.0.7", "username": "bob",
          "extra_data": {"event_id": 4740}}
    alerts = []
    for _ in range(3):
        alerts += corr.process(ev)
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "account_lockout_storm"


def test_sliding_window_prunes_old_events():
    counter = SlidingWindowCounter(window_seconds=10)
    now = time.time()
    # Pruning is relative to the latest recorded timestamp, so an old
    # event counts until a newer event arrives and pushes it out.
    assert counter.record("k", timestamp=now - 30) == 1
    assert counter.record("k", timestamp=now) == 1  # the 30s-old one is pruned
    assert counter.record("k", timestamp=now) == 2
