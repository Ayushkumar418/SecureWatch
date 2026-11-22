"""Tests for api/app.py — exercised through Flask's test client.

No PostgreSQL is running in this environment, so every DB call fails and
the API must fall back to the in-memory store. These tests pin that
behaviour: demo mode works end-to-end with zero keys and no database.
"""
from datetime import datetime, timezone

import pytest

import config
from models import mem_store


@pytest.fixture(autouse=True)
def _reset_store(monkeypatch):
    mem_store.reset()
    monkeypatch.setattr(config, "DEMO_MODE", True)
    yield
    mem_store.reset()


@pytest.fixture()
def client():
    from api.app import app
    app.config["TESTING"] = True
    return app.test_client()


def _seed_event(**kw):
    kw.setdefault("timestamp", datetime.now(timezone.utc))
    kw.setdefault("severity", "INFO")
    kw.setdefault("message", "seed event")
    kw.setdefault("source_name", "apache")
    return mem_store.insert_event(**kw)


def test_root_returns_api_info(client):
    r = client.get("/")
    assert r.status_code == 200
    body = r.get_json()
    assert body["name"] == "SecureWatch AI"
    assert body["endpoints"]["health"] == "/api/health"
    assert body["endpoints"]["threat_intel"] == "/api/threat-intel/<ip>"


def test_health_is_200_without_postgres(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.get_json()
    assert body["status"] == "ok"
    assert body["mode"] == "demo"
    assert body["db"] == "unavailable"
    assert body["uptime_seconds"] >= 0
    assert body["version"] == "3.0"


def test_stats_shape(client):
    _seed_event(ip_address="8.8.8.8")
    _seed_event(source_name="auth", severity="WARNING")
    mem_store.insert_alert("sqli_attempt", "CRITICAL", "SQLi")
    r = client.get("/api/stats")
    assert r.status_code == 200
    body = r.get_json()
    assert body["events_24h"] == 2
    assert body["active_alerts"] == 1
    assert body["alerts_by_severity"] == {"CRITICAL": 1}
    assert body["events_by_source"] == {"apache": 1, "auth": 1}
    assert body["top_attacking_ips"] == [{"ip": "8.8.8.8", "count": 1}]
    assert "timeline" in body


def test_events_list_filters_and_pagination(client):
    for i in range(3):
        _seed_event(message=f"GET /page{i}")
    _seed_event(source_name="auth", severity="WARNING", message="bad login")
    r = client.get("/api/events?source=apache")
    assert r.status_code == 200
    assert r.get_json()["total"] == 3
    r = client.get("/api/events?search=bad%20login")
    assert r.get_json()["total"] == 1
    r = client.get("/api/events?limit=2&offset=2")
    assert len(r.get_json()["events"]) == 2


def test_get_single_event_and_404(client):
    eid = _seed_event(message="single event")
    r = client.get(f"/api/events/{eid}")
    assert r.status_code == 200
    assert r.get_json()["message"] == "single event"
    assert client.get("/api/events/9999").status_code == 404


def test_alerts_list_and_resolve_flow(client):
    aid = mem_store.insert_alert("ssh_brute_force", "CRITICAL", "SSH Brute Force")
    r = client.get("/api/alerts")
    assert r.status_code == 200
    assert r.get_json()["count"] == 1

    r = client.get(f"/api/alerts/{aid}")
    assert r.status_code == 200
    assert r.get_json()["is_resolved"] is False
    assert client.get("/api/alerts/9999").status_code == 404

    r = client.post(f"/api/alerts/{aid}/resolve")
    assert r.status_code == 200
    assert r.get_json()["is_resolved"] is True
    assert client.get(f"/api/alerts/{aid}").get_json()["is_resolved"] is True
    assert client.get("/api/alerts?resolved=true").get_json()["count"] == 1
    assert client.post("/api/alerts/9999/resolve").status_code == 404


def test_ai_status_falls_back_in_demo_mode(client):
    r = client.get("/api/ai-status")
    assert r.status_code == 200
    body = r.get_json()
    assert body["banner"]["type"] == "info"
    assert body["history"] == []
