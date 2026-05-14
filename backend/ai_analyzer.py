"""
ai_analyzer.py — Smart AI Analyzer with fallback system.

Priority order:
  1. Google Gemini API (free tier) — if GEMINI_API_KEY set + quota available
  2. Anthropic Claude API          — if ANTHROPIC_API_KEY set + credits available
  3. Hardcoded rule-based analysis — always works, no API needed

Dashboard is notified of AI status via a status table in DB.

Run:  python ai_analyzer.py
"""
import os
import time
import json
import logging
from datetime import datetime, timezone
from dotenv import load_dotenv

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from models.db import get_conn

load_dotenv()

POLL_INTERVAL = 30

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ai_analyzer] %(levelname)s %(message)s"
)
log = logging.getLogger("ai_analyzer")


# ── DB: create ai_status table for dashboard notifications ────────────────

def ensure_status_table():
    """Create a table to store AI service status for the dashboard."""
    sql = """
        CREATE TABLE IF NOT EXISTS ai_status (
            id          SERIAL PRIMARY KEY,
            provider    VARCHAR(50)  NOT NULL,   -- gemini | anthropic | fallback
            status      VARCHAR(50)  NOT NULL,   -- active | rate_limited | no_key | error
            message     TEXT,
            updated_at  TIMESTAMPTZ DEFAULT NOW()
        );
        -- Only keep one row (upsert by provider)
        INSERT INTO ai_status (provider, status, message)
        VALUES ('system', 'starting', 'AI Analyzer is initializing...')
        ON CONFLICT DO NOTHING;
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)


def update_ai_status(provider: str, status: str, message: str):
    """Update the AI status so the dashboard can show it."""
    sql = """
        INSERT INTO ai_status (provider, status, message, updated_at)
        VALUES (%s, %s, %s, NOW())
        ON CONFLICT (provider) DO UPDATE
            SET status     = EXCLUDED.status,
                message    = EXCLUDED.message,
                updated_at = NOW()
    """
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # Add unique constraint if not exists
                cur.execute("""
                    DO $$
                    BEGIN
                        IF NOT EXISTS (
                            SELECT 1 FROM pg_constraint
                            WHERE conname = 'ai_status_provider_unique'
                        ) THEN
                            ALTER TABLE ai_status
                            ADD CONSTRAINT ai_status_provider_unique UNIQUE (provider);
                        END IF;
                    END $$;
                """)
                cur.execute(sql, (provider, status, message))
    except Exception as e:
        log.debug("Could not update AI status: %s", e)


# ── Hardcoded rule-based fallback analysis ────────────────────────────────

RULE_ANALYSIS = {
    "ssh_brute_force": {
        "threat_summary": "Multiple failed SSH login attempts detected from a single IP address in a short time window, indicating an automated brute force attack trying to guess valid credentials.",
        "why_dangerous": "If successful, the attacker gains full shell access to the server and can install malware, steal data, or use it as a pivot point.",
        "attacker_intent": "brute_force",
        "confidence": "HIGH",
        "recommended_action": "Immediately block the attacking IP using: sudo ufw deny from <IP> to any. Also consider installing fail2ban for automatic blocking.",
        "severity_reasoning": "CRITICAL because brute force attacks directly target system access and have a high likelihood of success against weak passwords."
    },
    "http_scan": {
        "threat_summary": "A high volume of HTTP 404 errors from one IP indicates automated scanning for vulnerable paths like /admin, /.env, or /wp-login.php.",
        "why_dangerous": "Scanners are reconnaissance tools — if they find an exposed endpoint, the attacker will immediately exploit it.",
        "attacker_intent": "reconnaissance",
        "confidence": "HIGH",
        "recommended_action": "Block the scanning IP in your firewall or Nginx config. Add rate limiting: max 20 requests/minute per IP.",
        "severity_reasoning": "HIGH because active scanning almost always precedes a targeted attack on discovered vulnerabilities."
    },
    "sqli_attempt": {
        "threat_summary": "SQL injection payload detected in an HTTP request URL. The attacker is attempting to manipulate your database queries to extract or modify data.",
        "why_dangerous": "A successful SQL injection can expose your entire database including usernames, passwords, and sensitive records.",
        "attacker_intent": "data_exfiltration",
        "confidence": "HIGH",
        "recommended_action": "Block the IP immediately. Review your application code for parameterized queries. Check database logs for any successful injections.",
        "severity_reasoning": "CRITICAL because SQL injection is one of the most dangerous web vulnerabilities and can lead to complete database compromise."
    },
    "sensitive_path": {
        "threat_summary": "A request was made to a sensitive file path such as /.env, /.git, or /phpmyadmin, which could expose configuration files or credentials.",
        "why_dangerous": "Exposed .env files often contain database passwords and API keys that give full system access.",
        "attacker_intent": "reconnaissance",
        "confidence": "MEDIUM",
        "recommended_action": "Block access to sensitive paths in your web server config. Verify these files are not publicly accessible.",
        "severity_reasoning": "HIGH because exposure of configuration files can immediately lead to full system compromise."
    },
    "user_created": {
        "threat_summary": "A new system user account was created, which may indicate an attacker establishing persistence after gaining initial access to the system.",
        "why_dangerous": "Backdoor accounts allow attackers to maintain access even if their initial entry point is closed.",
        "attacker_intent": "privilege_escalation",
        "confidence": "MEDIUM",
        "recommended_action": "Verify this user creation was authorized. If not, delete the account immediately: sudo userdel -r <username> and audit how access was gained.",
        "severity_reasoning": "HIGH because unauthorized user creation is a classic persistence technique used after system compromise."
    },
    "oom_kill": {
        "threat_summary": "The Linux kernel killed a process due to critically low memory. This can be caused by a memory leak, a resource exhaustion attack, or a misconfigured application.",
        "why_dangerous": "Repeated OOM kills degrade system stability and can be exploited as a denial-of-service vector.",
        "attacker_intent": "unknown",
        "confidence": "LOW",
        "recommended_action": "Check which process was killed and investigate its memory usage. Consider adding more RAM or setting memory limits for high-usage processes.",
        "severity_reasoning": "MEDIUM because while OOM kills may be benign, repeated occurrences suggest a resource problem that needs investigation."
    },
    "root_login": {
        "threat_summary": "A direct root login via SSH was detected. This is extremely dangerous and usually indicates either a compromised root password or an insider threat.",
        "why_dangerous": "Root access gives complete control over the entire system with no restrictions whatsoever.",
        "attacker_intent": "privilege_escalation",
        "confidence": "HIGH",
        "recommended_action": "Disable root SSH login immediately: set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart SSH. Investigate who logged in and from where.",
        "severity_reasoning": "CRITICAL because direct root access means the attacker has unrestricted control of the entire system."
    },
    "password_changed": {
        "threat_summary": "A user account password was changed on the system. This could be a normal administrative action or an attacker locking out legitimate users.",
        "why_dangerous": "Unauthorized password changes can lock out legitimate users and give attackers persistent access.",
        "attacker_intent": "privilege_escalation",
        "confidence": "LOW",
        "recommended_action": "Verify this change was authorized by checking with the user and reviewing recent login activity for that account.",
        "severity_reasoning": "MEDIUM because password changes require investigation to confirm they were authorized."
    },
}

DEFAULT_ANALYSIS = {
    "threat_summary": "A security event was detected that requires investigation by the security team.",
    "why_dangerous": "Unreviewed security events can indicate the early stages of a cyberattack.",
    "attacker_intent": "unknown",
    "confidence": "LOW",
    "recommended_action": "Review the raw log entries for this alert and investigate the source IP and affected user accounts.",
    "severity_reasoning": "Assigned based on automated detection rules — manual review recommended."
}


def get_fallback_analysis(alert: dict) -> dict:
    """Return rule-based analysis based on alert rule_name."""
    rule = alert.get('rule_name', '').lower()
    # Try exact match first, then partial match
    if rule in RULE_ANALYSIS:
        return RULE_ANALYSIS[rule]
    for key in RULE_ANALYSIS:
        if key in rule or rule in key:
            return RULE_ANALYSIS[key]
    return DEFAULT_ANALYSIS


def format_explanation(analysis: dict, source: str = "AI") -> str:
    intent = analysis.get('attacker_intent', 'unknown').replace('_', ' ').title()
    source_tag = f"[{source}]" if source != "AI" else ""
    return (
        f"🔍 THREAT SUMMARY {source_tag}\n"
        f"{analysis.get('threat_summary', 'N/A')}\n\n"
        f"⚠️  WHY DANGEROUS\n"
        f"{analysis.get('why_dangerous', 'N/A')}\n\n"
        f"🎯 ATTACKER INTENT: {intent}\n"
        f"📊 CONFIDENCE: {analysis.get('confidence', 'N/A')}\n\n"
        f"✅ RECOMMENDED ACTION\n"
        f"{analysis.get('recommended_action', 'N/A')}\n\n"
        f"📝 SEVERITY REASONING\n"
        f"{analysis.get('severity_reasoning', 'N/A')}"
    )


# ── Gemini API integration ─────────────────────────────────────────────────

def try_gemini(alert: dict) -> dict | None:
    """Try Google Gemini API. Returns analysis dict or None."""
    try:
        from google import genai
        from google.genai import types
    except ImportError:
        try:
            import google.generativeai as genai_old
            # fallback to old library
            return _try_gemini_old(alert, genai_old)
        except ImportError:
            log.debug("google-generativeai not installed")
            return None

    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key or "your-key" in api_key:
        return None

    try:
        client = genai.Client(api_key=api_key)
        prompt = _build_prompt(alert)
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
        )
        raw = response.text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw.strip())
    except Exception as e:
        err = str(e)
        if "429" in err or "quota" in err.lower() or "rate" in err.lower():
            log.warning("Gemini rate limit hit — switching to fallback")
            update_ai_status("gemini", "rate_limited",
                "⚠️ Gemini free tier quota reached (15 req/min). Using rule-based analysis.")
        else:
            log.error("Gemini error: %s", e)
            update_ai_status("gemini", "error", f"Gemini API error: {err[:100]}")
        return None


def _try_gemini_old(alert: dict, genai) -> dict | None:
    """Fallback for old google-generativeai package."""
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key or "your-key" in api_key:
        return None
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.0-flash")
        response = model.generate_content(_build_prompt(alert))
        raw = response.text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw.strip())
    except Exception as e:
        err = str(e)
        if "429" in err or "quota" in err.lower():
            update_ai_status("gemini", "rate_limited",
                "⚠️ Gemini free tier quota reached. Using rule-based analysis.")
        return None


# ── Anthropic API integration ──────────────────────────────────────────────

def try_anthropic(alert: dict) -> dict | None:
    """Try Anthropic Claude API. Returns analysis dict or None."""
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key or "your-key" in api_key:
        return None
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=500,
            system="You are a senior cybersecurity analyst. Respond ONLY with valid JSON — no markdown fences.",
            messages=[{"role": "user", "content": _build_prompt(alert)}]
        )
        raw = message.content[0].text.strip()
        return json.loads(raw)
    except Exception as e:
        err = str(e)
        if "credit" in err.lower() or "balance" in err.lower():
            update_ai_status("anthropic", "no_credits",
                "⚠️ Anthropic API: insufficient credits. Add credits at console.anthropic.com")
        return None


# ── Shared prompt builder ─────────────────────────────────────────────────

def _build_prompt(alert: dict) -> str:
    return f"""You are a senior cybersecurity analyst AI inside a SIEM system.
Respond ONLY with a valid JSON object — no preamble, no markdown fences.
Use this exact structure:
{{
  "threat_summary": "1-2 sentence plain English explanation",
  "why_dangerous": "1 sentence risk if ignored",
  "attacker_intent": "brute_force | data_exfiltration | reconnaissance | privilege_escalation | web_attack | unknown",
  "confidence": "HIGH | MEDIUM | LOW",
  "recommended_action": "Specific step the team should take right now",
  "severity_reasoning": "1 sentence explaining the severity level"
}}

Analyze this SIEM alert:
Rule:           {alert['rule_name']}
Severity:       {alert['severity']}
Title:          {alert['title']}
Description:    {alert['description'] or 'N/A'}
IPs involved:   {', '.join(alert['related_ips'] or []) or 'None'}
Users targeted: {', '.join(alert['related_users'] or []) or 'None'}
Event count:    {alert['event_count']}"""


# ── DB helpers ────────────────────────────────────────────────────────────

def fetch_unanalyzed_alerts() -> list[dict]:
    sql = """
        SELECT id, rule_name, severity, title, description,
               related_ips, related_users, event_count, created_at
        FROM   alerts
        WHERE  ai_explanation IS NULL
          AND  is_resolved    = FALSE
        ORDER  BY created_at DESC
        LIMIT  10
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]


def save_explanation(alert_id: int, explanation: str):
    sql = "UPDATE alerts SET ai_explanation = %s WHERE id = %s"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (explanation, alert_id))


# ── New API endpoint helper (add to api/app.py) ───────────────────────────

# Add this to api/app.py:
#
# @app.get("/api/ai-status")
# def ai_status():
#     sql = "SELECT provider, status, message, updated_at FROM ai_status ORDER BY updated_at DESC"
#     with get_conn() as conn:
#         with conn.cursor() as cur:
#             cur.execute(sql)
#             cols = [d[0] for d in cur.description]
#             rows = [dict(zip(cols, r)) for r in cur.fetchall()]
#             for r in rows:
#                 if isinstance(r.get('updated_at'), datetime):
#                     r['updated_at'] = r['updated_at'].isoformat()
#     return jsonify({"ai_status": rows})


# ── Main loop ─────────────────────────────────────────────────────────────

def run():
    ensure_status_table()

    gemini_key    = os.getenv("GEMINI_API_KEY", "")
    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")

    has_gemini    = bool(gemini_key and "your-key" not in gemini_key)
    has_anthropic = bool(anthropic_key and "your-key" not in anthropic_key)

    log.info("=" * 55)
    log.info("  SIEM AI Analyzer — Smart Fallback System")
    log.info("  Gemini API:    %s", "✅ Key found" if has_gemini    else "❌ No key")
    log.info("  Anthropic API: %s", "✅ Key found" if has_anthropic else "❌ No key")
    log.info("  Fallback:      ✅ Rule-based (always available)")
    log.info("=" * 55)

    if not has_gemini and not has_anthropic:
        msg = "No AI API key found. Using rule-based analysis. Add GEMINI_API_KEY to .env for AI-powered analysis."
        log.warning(msg)
        update_ai_status("system", "no_key", "⚠️ " + msg)
    elif has_gemini:
        update_ai_status("gemini", "active", "✅ Gemini API active — gemini-2.0-flash free tier")
    elif has_anthropic:
        update_ai_status("anthropic", "active", "✅ Anthropic API active — claude-sonnet-4-6")

    log.info("Polling every %ds for new alerts.", POLL_INTERVAL)

    while True:
        try:
            alerts = fetch_unanalyzed_alerts()

            if alerts:
                log.info("Found %d unanalyzed alert(s).", len(alerts))

                for alert in alerts:
                    analysis = None
                    source   = "Fallback"

                    # 1. Try Gemini first
                    if has_gemini:
                        analysis = try_gemini(alert)
                        if analysis:
                            source = "Gemini AI"
                            update_ai_status("gemini", "active",
                                "✅ Gemini API active — gemini-2.0-flash")

                    # 2. Try Anthropic if Gemini failed
                    if not analysis and has_anthropic:
                        analysis = try_anthropic(alert)
                        if analysis:
                            source = "Claude AI"
                            update_ai_status("anthropic", "active",
                                "✅ Anthropic API active — claude-sonnet-4-6")

                    # 3. Always-available fallback
                    if not analysis:
                        analysis = get_fallback_analysis(alert)
                        source   = "Rule-Based"
                        update_ai_status("system", "fallback",
                            "ℹ️ Using rule-based analysis (AI API unavailable or rate limited)")

                    explanation = format_explanation(analysis, source)
                    save_explanation(alert['id'], explanation)

                    icon = "🤖" if "AI" in source else "📋"
                    log.info(
                        "  %s Alert #%s — %s | intent: %s | confidence: %s",
                        icon, alert['id'], source,
                        analysis.get('attacker_intent', '?'),
                        analysis.get('confidence', '?')
                    )
                    time.sleep(2)

            else:
                log.debug("No unanalyzed alerts.")

        except Exception as e:
            log.error("Main loop error: %s", e, exc_info=True)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
