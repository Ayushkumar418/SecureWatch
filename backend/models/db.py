"""
db.py — PostgreSQL connection pool (shared across agents + API)
"""
import os
import json
import psycopg2
from psycopg2 import pool
from contextlib import contextmanager
from dotenv import load_dotenv

load_dotenv()

_pool = None


def get_pool():
    global _pool
    if _pool is None:
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


def ensure_schema():
    """Run schema migrations to add new columns if they don't exist."""
    migrations = [
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS host VARCHAR(255) DEFAULT 'localhost'",
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS os_type VARCHAR(20) DEFAULT 'linux'",
        "CREATE INDEX IF NOT EXISTS idx_events_host ON events(host)",
        "CREATE INDEX IF NOT EXISTS idx_events_os_type ON events(os_type)",
    ]
    with get_conn() as conn:
        with conn.cursor() as cur:
            for sql in migrations:
                try:
                    cur.execute(sql)
                except Exception:
                    pass  # column/index already exists
