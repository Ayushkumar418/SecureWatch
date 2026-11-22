"""
db.py — PostgreSQL connection pool (shared across agents + API)
"""
import logging
import os
import json
import time
from pathlib import Path

import psycopg2
from psycopg2 import pool
from contextlib import contextmanager
from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger(__name__)

_pool = None
_pool_failed_at = None  # monotonic timestamp of the last failed connect
POOL_RETRY_SECONDS = 30  # wait this long before retrying a failed connect


class DbUnavailable(Exception):
    """Raised when PostgreSQL is not reachable."""
    pass


def get_pool():
    """Return the shared connection pool, creating it on first use.

    A failed connect is remembered only for POOL_RETRY_SECONDS — after the
    cooldown the next call tries again, so PostgreSQL starting *after* the
    backend no longer requires a backend restart to recover.
    """
    global _pool, _pool_failed_at
    if _pool is not None:
        return _pool
    if _pool_failed_at is not None:
        if time.monotonic() - _pool_failed_at < POOL_RETRY_SECONDS:
            raise DbUnavailable("PostgreSQL not available")
        _pool_failed_at = None  # cooldown expired — try connecting again
    try:
        _pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=2,
            maxconn=10,
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", 5432)),
            dbname=os.getenv("DB_NAME", "siem_db"),
            user=os.getenv("DB_USER", "siem_user"),
            password=os.getenv("DB_PASSWORD", os.getenv("DB_PASS", "siem_pass")),
        )
        return _pool
    except Exception:
        _pool_failed_at = time.monotonic()
        raise DbUnavailable("PostgreSQL not available")


@contextmanager
def get_conn():
    """Usage:  with get_conn() as conn: ..."""
    pool = get_pool()
    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


def insert_event(source_name, timestamp, severity, message,
                 raw_log=None, ip_address=None, username=None,
                 event_type=None, extra_data=None,
                 host=None, os_type=None):
    """Insert a single normalized log event into the events table."""
    sql = """
        INSERT INTO events
            (source_name, timestamp, severity, message,
             raw_log, ip_address, username, event_type, extra_data,
             host, os_type)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id;
    """
    extra = json.dumps(extra_data or {})
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (
                source_name, timestamp, severity, message,
                raw_log, ip_address, username, event_type, extra,
                host, os_type
            ))
            return cur.fetchone()[0]


def insert_alert(rule_name, severity, title, description=None,
                 ai_explanation=None, related_ips=None,
                 related_users=None, event_count=1):
    """Insert a new alert record."""
    sql = """
        INSERT INTO alerts
            (rule_name, severity, title, description,
             ai_explanation, related_ips, related_users, event_count)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id;
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (
                rule_name, severity, title, description,
                ai_explanation, related_ips or [], related_users or [],
                event_count
            ))
            return cur.fetchone()[0]


def _split_sql_script(script):
    """Split a SQL script into individual statements.

    Strips full-line `--` comments and drops empty statements, so a failure
    can be reported against the exact statement that failed.
    """
    lines = [ln for ln in script.splitlines()
             if not ln.strip().startswith("--")]
    statements = []
    for chunk in "\n".join(lines).split(";"):
        stmt = chunk.strip()
        if stmt:
            statements.append(stmt)
    return statements


# Migrations that live in code rather than schema.sql (kept for databases
# created before schema.sql held these definitions).
_EXTRA_MIGRATIONS = [
    # Host / OS columns added after the first schema version.
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS host VARCHAR(255) DEFAULT 'localhost'",
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS os_type VARCHAR(20) DEFAULT 'linux'",
    "CREATE INDEX IF NOT EXISTS idx_events_host ON events(host)",
    "CREATE INDEX IF NOT EXISTS idx_events_os_type ON events(os_type)",
    # ai_status + email_sent predate schema.sql holding them; keep the
    # migrations so old databases are brought up to date too.
    """CREATE TABLE IF NOT EXISTS ai_status (
           id          SERIAL PRIMARY KEY,
           provider    VARCHAR(50) NOT NULL,
           status      VARCHAR(50) NOT NULL,
           message     TEXT,
           updated_at  TIMESTAMPTZ DEFAULT NOW(),
           CONSTRAINT ai_status_provider_unique UNIQUE (provider)
       )""",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS email_sent BOOLEAN DEFAULT FALSE",
]


def ensure_schema():
    """Create every table, index and seed row the app needs, if missing.

    Runs models/schema.sql plus the extra migrations above. Safe to call on
    every startup (everything is IF NOT EXISTS) and safe to call twice.

    Returns the number of statements executed. Raises on failure — a fresh
    database that cannot be created must be loud, never a silent pass:
    main.py exits in live mode when this raises, and warns in demo mode.
    """
    schema_path = Path(__file__).parent / "schema.sql"
    if not schema_path.exists():
        raise FileNotFoundError(f"Schema file not found: {schema_path}")
    statements = _split_sql_script(schema_path.read_text(encoding="utf-8"))
    statements += _EXTRA_MIGRATIONS

    applied = 0
    with get_conn() as conn:
        with conn.cursor() as cur:
            for sql in statements:
                try:
                    cur.execute(sql)
                except Exception as exc:
                    # Roll back happens in get_conn(); report the exact
                    # statement instead of swallowing it.
                    raise RuntimeError(
                        f"Schema migration failed, statement #{applied + 1}: "
                        f"{sql[:120]}... ({exc})"
                    ) from exc
                applied += 1
    log.info("Schema ensured: %d statements applied", applied)
    return applied
