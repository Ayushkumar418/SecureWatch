"""Tests for config.py defaults and models/mem_store.py."""
from datetime import datetime, timezone, timedelta

import config
from models import mem_store


def test_config_defaults():
    assert config.API_PORT == 5000
    assert config.API_HOST == "0.0.0.0"
    assert config.DB_NAME == "siem_db"
    assert config.BF_THRESHOLD == 5
    assert config.BF_WINDOW == 120
    assert config.SCAN_THRESHOLD == 20
    assert config.SCAN_WINDOW == 30
    assert isinstance(config.DEMO_MODE, bool)
    assert isinstance(config.TAIL_SLEEP, float)
    assert set(config.LINUX_LOG_PATHS) == {"auth", "syslog", "kern", "apache", "nginx"}


def test_mem_store_insert_and_get_event():
    mem_store.reset()
    eid = mem_store.insert_event("auth", datetime.now(timezone.utc), "WARNING",
                                 "SSH failed", ip_address="1.2.3.4",
                                 username="root", event_type="failed_password")
    assert eid == 1
    ev = mem_store.get_event(1)
    assert ev["message"] == "SSH failed"
    assert ev["ip_address"] == "1.2.3.4"
    assert isinstance(ev["timestamp"], str)  # serializable copy
    assert mem_store.get_event(999) is None


def test_mem_store_event_filters_and_pagination():
    mem_store.reset()
    now = datetime.now(timezone.utc)
    for i in range(5):
        mem_store.insert_event("apache", now, "INFO", f"GET /page{i}")
    mem_store.insert_event("auth", now, "WARNING", "bad login")
    events, total = mem_store.get_events(source="apache")
    assert total == 5
    assert all(e["source_name"] == "apache" for e in events)
    events, total = mem_store.get_events(search="bad login")
    assert total == 1
    events, total = mem_store.get_events(limit=2, offset=0)
    assert len(events) == 2 and total == 6
    events, total = mem_store.get_events(limit=2, offset=4)
    assert len(events) == 2


def test_mem_store_alerts_and_resolve():
    mem_store.reset()
    aid = mem_store.insert_alert("ssh_brute_force", "CRITICAL",
                                 "SSH Brute Force", related_ips=["9.9.9.9"])
    assert aid == 1
    assert mem_store.get_alert(1)["title"] == "SSH Brute Force"
    assert mem_store.get_alert(999) is None
    assert len(mem_store.get_alerts(resolved=False)) == 1
    assert mem_store.get_alerts(resolved=True) == []
    resolved = mem_store.resolve_alert(1)
    assert resolved["is_resolved"] is True
    assert resolved["resolved_at"] is not None
    assert mem_store.resolve_alert(999) is None
    assert len(mem_store.get_alerts(resolved=True)) == 1


def test_mem_store_stats():
    mem_store.reset()
    now = datetime.now(timezone.utc)
    mem_store.insert_event("apache", now, "INFO", "GET /")
    mem_store.insert_event("apache", now, "INFO", "GET /x", ip_address="8.8.8.8")
    mem_store.insert_event("auth", now - timedelta(hours=25), "INFO", "old event")
    mem_store.insert_alert("sqli_attempt", "CRITICAL", "SQLi")
    stats = mem_store.get_stats()
    assert stats["events_24h"] == 2  # the 25h-old event is excluded
    assert stats["active_alerts"] == 1
    assert stats["alerts_by_severity"] == {"CRITICAL": 1}
    assert stats["events_by_source"] == {"apache": 2}
    assert stats["top_attacking_ips"] == [{"ip": "8.8.8.8", "count": 1}]
    assert len(stats["timeline"]) == 1
