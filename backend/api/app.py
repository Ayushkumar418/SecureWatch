"""
app.py — Flask REST API for the SIEM dashboard.

Endpoints:
  GET  /api/events          list events (filter: source, severity, limit)
  GET  /api/events/<id>     single event detail
  GET  /api/alerts          list alerts (filter: severity, resolved)
  POST /api/alerts/<id>/resolve   mark alert resolved
  GET  /api/stats           dashboard summary numbers
  GET  /api/health          health check

Run:  python api/app.py
"""
import os
import json
import logging
from datetime import datetime, timezone

import psycopg2.extras
from flask import Flask, jsonify, request, abort
from flask_cors import CORS

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from models.db import get_conn

app = Flask(__name__)
CORS(app, origins=["http://192.168.56.101:3000", "http://localhost:3000"])   # allow React dev server (localhost:3000) to call us

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("siem_api")


# ── helpers ───────────────────────────────────────────────────────────────

def row_to_dict(row, cursor):
    """Convert psycopg2 tuple row → dict using cursor.description."""
    cols = [desc[0] for desc in cursor.description]
    d = dict(zip(cols, row))
    # Make datetimes JSON-serializable
    for k, v in d.items():
        if isinstance(v, datetime):
            d[k] = v.isoformat()
    return d


def rows_to_list(cursor):
    return [row_to_dict(r, cursor) for r in cursor.fetchall()]


def parse_int(val, default, min_v=1, max_v=1000):
    try:
        return max(min_v, min(int(val), max_v))
    except (TypeError, ValueError):
        return default


# ── events ────────────────────────────────────────────────────────────────

@app.get("/api/events")
def list_events():
    """
    Query params:
      source   — ssh | apache | syslog
      severity — INFO | WARNING | ERROR | CRITICAL
      limit    — 1-500 (default 100)
      offset   — pagination offset (default 0)
      search   — text search in message
    """
    source   = request.args.get("source")
    severity = request.args.get("severity")
    search   = request.args.get("search")
    limit    = parse_int(request.args.get("limit"), 100, max_v=500)
    offset   = parse_int(request.args.get("offset"), 0, min_v=0)

    conditions = []
    params     = []

    if source:
        conditions.append("source_name = %s")
        params.append(source)
    if severity:
        conditions.append("severity = %s")
        params.append(severity.upper())
    if search:
        conditions.append("message ILIKE %s")
        params.append(f"%{search}%")

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql   = f"""
        SELECT id, source_name, timestamp, severity,
               message, ip_address, username, event_type, extra_data
        FROM   events
        {where}
        ORDER  BY timestamp DESC
        LIMIT  %s OFFSET %s
    """
    params += [limit, offset]

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            events = rows_to_list(cur)

    return jsonify({"events": events, "count": len(events)})


@app.get("/api/events/<int:event_id>")
def get_event(event_id):
    sql = "SELECT * FROM events WHERE id = %s"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (event_id,))
            row = cur.fetchone()
            if not row:
                abort(404)
            return jsonify(row_to_dict(row, cur))


# ── alerts ────────────────────────────────────────────────────────────────

@app.get("/api/alerts")
def list_alerts():
    resolved = request.args.get("resolved", "false").lower() == "true"
    severity = request.args.get("severity")
    limit    = parse_int(request.args.get("limit"), 50, max_v=200)

    conditions = [f"is_resolved = %s"]
    params     = [resolved]

    if severity:
        conditions.append("severity = %s")
        params.append(severity.upper())

    where = "WHERE " + " AND ".join(conditions)
    sql   = f"""
        SELECT id, rule_name, severity, title, description,
               ai_explanation, related_ips, related_users,
               event_count, is_resolved, created_at, resolved_at
        FROM   alerts
        {where}
        ORDER  BY created_at DESC
        LIMIT  %s
    """
    params.append(limit)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            alerts = rows_to_list(cur)

    return jsonify({"alerts": alerts, "count": len(alerts)})


@app.post("/api/alerts/<int:alert_id>/resolve")
def resolve_alert(alert_id):
    sql = """
        UPDATE alerts
        SET    is_resolved = TRUE,
               resolved_at = NOW()
        WHERE  id = %s
        RETURNING id, is_resolved, resolved_at
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (alert_id,))
            row = cur.fetchone()
            if not row:
                abort(404)
            result = row_to_dict(row, cur)

    log.info("Alert %s resolved", alert_id)
    return jsonify(result)


# ── stats / dashboard summary ─────────────────────────────────────────────

@app.get("/api/stats")
def stats():
    """Returns counts for the dashboard top cards."""
    with get_conn() as conn:
        with conn.cursor() as cur:

            # Total events (last 24h)
            cur.execute("""
                SELECT COUNT(*) FROM events
                WHERE timestamp >= NOW() - INTERVAL '24 hours'
            """)
            events_24h = cur.fetchone()[0]

            # Active (unresolved) alerts by severity
            cur.execute("""
                SELECT severity, COUNT(*) FROM alerts
                WHERE is_resolved = FALSE
                GROUP BY severity
            """)
            alert_rows = cur.fetchall()
            alerts_by_severity = {row[0]: row[1] for row in alert_rows}

            # Events by source (last 24h)
            cur.execute("""
                SELECT source_name, COUNT(*) FROM events
                WHERE timestamp >= NOW() - INTERVAL '24 hours'
                GROUP BY source_name
            """)
            source_rows   = cur.fetchall()
            events_by_src = {row[0]: row[1] for row in source_rows}

            # Events over time (last 24h, hourly buckets)
            cur.execute("""
                SELECT DATE_TRUNC('hour', timestamp) AS hour, COUNT(*) AS cnt
                FROM   events
                WHERE  timestamp >= NOW() - INTERVAL '24 hours'
                GROUP  BY hour
                ORDER  BY hour ASC
            """)
            timeline = [
                {"hour": row[0].isoformat(), "count": row[1]}
                for row in cur.fetchall()
            ]

            # Top attacking IPs
            cur.execute("""
                SELECT ip_address, COUNT(*) AS cnt FROM events
                WHERE  ip_address IS NOT NULL
                  AND  timestamp >= NOW() - INTERVAL '24 hours'
                GROUP  BY ip_address
                ORDER  BY cnt DESC
                LIMIT  5
            """)
            top_ips = [
                {"ip": row[0], "count": row[1]}
                for row in cur.fetchall()
            ]

    return jsonify({
        "events_24h":         events_24h,
        "active_alerts":      sum(alerts_by_severity.values()),
        "alerts_by_severity": alerts_by_severity,
        "events_by_source":   events_by_src,
        "timeline":           timeline,
        "top_attacking_ips":  top_ips,
    })


# ── AI status (for dashboard notification banner) ─────────────────────────

@app.get("/api/ai-status")
def ai_status():
    """
    Returns current AI analyzer status so the dashboard can show
    a banner like:
      ✅ "Gemini AI active"
      ⚠️  "Rate limit reached — using rule-based analysis"
      ❌  "No API key found — add GEMINI_API_KEY to .env"
    """
    try:
        sql = """
            SELECT provider, status, message, updated_at
            FROM   ai_status
            ORDER  BY updated_at DESC
            LIMIT  5
        """
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(sql)
                cols = [d[0] for d in cur.description]
                rows = []
                for row in cur.fetchall():
                    d = dict(zip(cols, row))
                    if isinstance(d.get("updated_at"), datetime):
                        d["updated_at"] = d["updated_at"].isoformat()
                    rows.append(d)

        # Determine overall banner type for frontend
        if not rows:
            banner = {
                "type":    "warning",
                "message": "⚠️ AI Analyzer not started yet. Run: python ai_analyzer.py"
            }
        else:
            latest = rows[0]
            status = latest.get("status", "")
            if status in ("active",):
                banner = {"type": "success", "message": latest["message"]}
            elif status in ("rate_limited",):
                banner = {"type": "warning", "message": latest["message"]}
            elif status in ("no_key",):
                banner = {"type": "error",
                          "message": "❌ No AI API key found. Add GEMINI_API_KEY to .env file."}
            elif status in ("no_credits",):
                banner = {"type": "error",
                          "message": "❌ API credits exhausted. Add credits or switch to Gemini free tier."}
            elif status in ("fallback",):
                banner = {"type": "info",
                          "message": "ℹ️ Using rule-based analysis (AI API unavailable or rate limited)"}
            else:
                banner = {"type": "info", "message": latest.get("message", "AI status unknown")}

        return jsonify({"banner": banner, "history": rows})

    except Exception as e:
        # ai_status table doesn't exist yet — analyzer not started
        return jsonify({
            "banner": {
                "type":    "warning",
                "message": "⚠️ AI Analyzer not started yet. Run: python ai_analyzer.py"
            },
            "history": []
        })


# ── health ────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        return jsonify({"status": "ok", "db": "connected"})
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)}), 500


# ── run ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
