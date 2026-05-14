"""
New API endpoints to add to api/app.py for Phase 3.

ADD these routes into your existing api/app.py file
(paste them before the  if __name__ == "__main__":  line)
"""

# ── GET single alert with full AI explanation ─────────────────────────────

"""
@app.get("/api/alerts/<int:alert_id>")
def get_alert(alert_id):
    sql = \"\"\"
        SELECT id, rule_name, severity, title, description,
               ai_explanation, related_ips, related_users,
               event_count, is_resolved, created_at, resolved_at
        FROM   alerts WHERE id = %s
    \"\"\"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (alert_id,))
            row = cur.fetchone()
            if not row:
                abort(404)
            return jsonify(row_to_dict(row, cur))


# ── POST: manually trigger AI analysis for one alert ─────────────────────

@app.post("/api/alerts/<int:alert_id>/analyze")
def analyze_now(alert_id):
    \"\"\"Force immediate AI analysis for a specific alert.\"\"\"
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from ai_analyzer import analyze_alert, format_explanation, save_explanation

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                \"\"\"SELECT id, rule_name, severity, title, description,
                          related_ips, related_users, event_count, created_at
                   FROM alerts WHERE id = %s\"\"\",
                (alert_id,)
            )
            row = cur.fetchone()
            if not row:
                abort(404)
            cols  = [d[0] for d in cur.description]
            alert = dict(zip(cols, row))

    analysis = analyze_alert(alert)
    if not analysis:
        return jsonify({"error": "AI analysis failed"}), 500

    explanation = format_explanation(analysis)
    save_explanation(alert_id, explanation)
    return jsonify({"alert_id": alert_id, "ai_explanation": explanation, "analysis": analysis})
"""
