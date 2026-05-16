"""
mem_store.py -- In-memory event/alert store for demo mode (no PostgreSQL).

Provides the same query interface as the DB so the API works
without any database. Data is lost when the server stops.
"""
import threading
from collections import defaultdict
from datetime import datetime, timezone, timedelta

_lock = threading.Lock()
_events = []       # list of dicts
_alerts = []       # list of dicts
_next_event_id = 1
_next_alert_id = 1

MAX_EVENTS = 5000  # cap to prevent memory bloat
MAX_ALERTS = 1000


def insert_event(source_name, timestamp, severity, message,
                 raw_log=None, ip_address=None, username=None,
                 event_type=None, extra_data=None,
                 host=None, os_type=None):
    """Store an event in memory. Returns the event id."""
    global _next_event_id
    with _lock:
        eid = _next_event_id
        _next_event_id += 1
        evt = {
            "id": eid,
            "source_name": source_name or "",
            "timestamp": timestamp or datetime.now(timezone.utc),
            "severity": severity or "INFO",
            "message": message or "",
            "raw_log": raw_log,
            "ip_address": ip_address,
            "username": username,
            "event_type": event_type,
            "extra_data": extra_data or {},
            "host": host or "",
            "os_type": os_type or "",
        }
        _events.append(evt)
        # Trim oldest if over cap
        if len(_events) > MAX_EVENTS:
            _events[:] = _events[-MAX_EVENTS:]
        return eid


def insert_alert(rule_name, severity, title, description=None,
                 ai_explanation=None, related_ips=None,
                 related_users=None, event_count=1):
    """Store an alert in memory. Returns the alert id."""
    global _next_alert_id
    with _lock:
        aid = _next_alert_id
        _next_alert_id += 1
        alert = {
            "id": aid,
            "rule_name": rule_name,
            "severity": severity,
            "title": title,
            "description": description,
            "ai_explanation": ai_explanation,
            "related_ips": related_ips or [],
            "related_users": related_users or [],
            "event_count": event_count,
            "is_resolved": False,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "resolved_at": None,
        }
        _alerts.append(alert)
        if len(_alerts) > MAX_ALERTS:
            _alerts[:] = _alerts[-MAX_ALERTS:]
        return aid


def get_stats():
    """Return dashboard stats from in-memory data."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)

    with _lock:
        # Events in last 24h
        recent = [e for e in _events if _to_dt(e["timestamp"]) >= cutoff]
        events_24h = len(recent)

        # Alerts by severity (unresolved)
        alerts_by_severity = defaultdict(int)
        for a in _alerts:
            if not a["is_resolved"]:
                alerts_by_severity[a["severity"]] += 1

        # Events by source
        events_by_source = defaultdict(int)
        for e in recent:
            events_by_source[e["source_name"]] += 1

        # Timeline (hourly buckets)
        buckets = defaultdict(int)
        for e in recent:
            dt = _to_dt(e["timestamp"])
            hour = dt.replace(minute=0, second=0, microsecond=0)
            buckets[hour.isoformat()] += 1
        timeline = [{"hour": h, "count": c} for h, c in sorted(buckets.items())]

        # Top attacking IPs
        ip_counts = defaultdict(int)
        for e in recent:
            ip = e.get("ip_address")
            if ip:
                ip_counts[ip] += 1
        top_ips = [{"ip": ip, "count": c}
                   for ip, c in sorted(ip_counts.items(), key=lambda x: -x[1])[:5]]

    return {
        "events_24h": events_24h,
        "active_alerts": sum(alerts_by_severity.values()),
        "alerts_by_severity": dict(alerts_by_severity),
        "events_by_source": dict(events_by_source),
        "timeline": timeline,
        "top_attacking_ips": top_ips,
    }


def get_events(source=None, severity=None, search=None, limit=100, offset=0):
    """Query in-memory events with filters."""
    with _lock:
        filtered = list(reversed(_events))  # newest first
        if source:
            filtered = [e for e in filtered if e["source_name"] == source]
        if severity:
            filtered = [e for e in filtered if e["severity"] == severity.upper()]
        if search:
            s = search.lower()
            filtered = [e for e in filtered if s in (e.get("message") or "").lower()]
        total = len(filtered)
        page = filtered[offset:offset + limit]
        # Make timestamps serializable
        result = []
        for e in page:
            ec = dict(e)
            if hasattr(ec.get("timestamp"), "isoformat"):
                ec["timestamp"] = ec["timestamp"].isoformat()
            result.append(ec)
        return result, total


def get_alerts(resolved=False, severity=None, limit=50):
    """Query in-memory alerts with filters."""
    with _lock:
        filtered = list(reversed(_alerts))  # newest first
        filtered = [a for a in filtered if a["is_resolved"] == resolved]
        if severity:
            filtered = [a for a in filtered if a["severity"] == severity.upper()]
        return filtered[:limit]


def resolve_alert(alert_id):
    """Mark an alert as resolved."""
    with _lock:
        for a in _alerts:
            if a["id"] == alert_id:
                a["is_resolved"] = True
                a["resolved_at"] = datetime.now(timezone.utc).isoformat()
                return a
    return None


def _to_dt(ts):
    """Convert a timestamp (datetime or str) to datetime."""
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)
    return datetime.now(timezone.utc)
