"""Tests for the database layer: schema creation, pool retry, log root.

Real-Postgres tests need a reachable server. They connect as the `postgres`
superuser (password from PG_SUPER_PASSWORD, default "postgres") to create a
throwaway `securewatch_test` database, and skip cleanly when no server is
available — so the suite still passes in CI without Postgres.
"""
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from models import db as db_module
from models.db import DbUnavailable, _split_sql_script, ensure_schema, get_pool

TEST_DB = "securewatch_test"

SUPER_DSN = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", 5432)),
    "dbname": "postgres",
    "user": "postgres",
    "password": os.getenv("PG_SUPER_PASSWORD", "postgres"),
}


def _pg_available():
    try:
        import psycopg2
        conn = psycopg2.connect(**SUPER_DSN)
        conn.close()
        return True
    except Exception:
        return False


@pytest.fixture(scope="module")
def test_db():
    """Create a fresh empty database and point the app's pool at it."""
    if not _pg_available():
        pytest.skip("PostgreSQL not available")
    import psycopg2
    from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

    admin = psycopg2.connect(**SUPER_DSN)
    admin.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    with admin.cursor() as cur:
        cur.execute(f'DROP DATABASE IF EXISTS "{TEST_DB}"')
        cur.execute(f'CREATE DATABASE "{TEST_DB}"')
    admin.close()

    old = {k: os.environ.get(k) for k in ("DB_NAME", "DB_USER", "DB_PASSWORD")}
    os.environ["DB_NAME"] = TEST_DB
    os.environ["DB_USER"] = SUPER_DSN["user"]
    os.environ["DB_PASSWORD"] = SUPER_DSN["password"]
    db_module._pool = None
    db_module._pool_failed_at = None
    yield TEST_DB

    db_module._pool = None
    db_module._pool_failed_at = None
    for k, v in old.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    admin = psycopg2.connect(**SUPER_DSN)
    admin.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    with admin.cursor() as cur:
        cur.execute(f'DROP DATABASE IF EXISTS "{TEST_DB}"')
    admin.close()


def _table_names(conn):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY 1"
        )
        return {row[0] for row in cur.fetchall()}


# ── Schema creation on a fresh database ───────────────────────────────────

def test_ensure_schema_creates_all_tables_on_fresh_db(test_db):
    applied = ensure_schema()
    assert applied > 0
    with db_module.get_conn() as conn:
        tables = _table_names(conn)
    assert {"log_sources", "events", "alerts", "ai_status"} <= tables


def test_ensure_schema_seeds_log_sources(test_db):
    ensure_schema()
    with db_module.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM log_sources")
            count = cur.fetchone()[0]
    assert count == 11  # the seed rows from schema.sql


def test_ensure_schema_is_idempotent(test_db):
    first = ensure_schema()
    second = ensure_schema()
    assert first == second
    with db_module.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM log_sources")
            assert cur.fetchone()[0] == 11


def test_insert_event_and_alert_round_trip(test_db):
    ensure_schema()
    event_id = db_module.insert_event(
        source_name="auth",
        timestamp=datetime.now(timezone.utc),
        severity="ERROR",
        message="Failed password for root from 1.2.3.4",
        ip_address="1.2.3.4",
        username="root",
        event_type="failed_logon",
    )
    alert_id = db_module.insert_alert(
        rule_name="ssh_brute_force",
        severity="HIGH",
        title="SSH brute force from 1.2.3.4",
        description="5 failed logins in 120s",
        related_ips=["1.2.3.4"],
        event_count=5,
    )
    with db_module.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT source_name, ip_address FROM events WHERE id = %s",
                (event_id,),
            )
            assert cur.fetchone() == ("auth", "1.2.3.4")
            cur.execute(
                "SELECT rule_name, is_resolved, email_sent FROM alerts WHERE id = %s",
                (alert_id,),
            )
            assert cur.fetchone() == ("ssh_brute_force", False, False)
            # cleanup: keep the test database tidy
            cur.execute("DELETE FROM events WHERE id = %s", (event_id,))
            cur.execute("DELETE FROM alerts WHERE id = %s", (alert_id,))


def test_ensure_schema_fails_loudly_when_db_is_down(monkeypatch):
    """A database that cannot be reached must raise, never silently pass."""
    monkeypatch.setenv("DB_PORT", "59999")  # nothing listens here
    db_module._pool = None
    db_module._pool_failed_at = None
    try:
        with pytest.raises(DbUnavailable):
            ensure_schema()
    finally:
        db_module._pool = None
        db_module._pool_failed_at = None


# ── SQL script splitting (no database needed) ─────────────────────────────

def test_split_sql_script_strips_comments_and_empties():
    script = """-- a comment
CREATE TABLE IF NOT EXISTS a (id INT);

-- another comment
CREATE TABLE IF NOT EXISTS b (id INT);
"""
    stmts = _split_sql_script(script)
    assert len(stmts) == 2
    assert stmts[0].startswith("CREATE TABLE IF NOT EXISTS a")
    assert stmts[1].startswith("CREATE TABLE IF NOT EXISTS b")


# ── Connection pool retry (no database needed) ────────────────────────────

def test_get_pool_retries_after_cooldown(monkeypatch):
    """A failed connect must not poison the pool forever."""
    import psycopg2.pool as pool_module

    calls = {"n": 0}
    real_pool = pool_module.ThreadedConnectionPool

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise Exception("connection refused")
        return "fake-pool"

    monkeypatch.setattr(pool_module, "ThreadedConnectionPool", flaky)
    monkeypatch.setattr(db_module, "POOL_RETRY_SECONDS", 0)
    db_module._pool = None
    db_module._pool_failed_at = None
    try:
        with pytest.raises(DbUnavailable):
            get_pool()
        assert get_pool() == "fake-pool"  # retried, did not stay failed
        assert calls["n"] == 2
    finally:
        db_module._pool = None
        db_module._pool_failed_at = None
        monkeypatch.setattr(pool_module, "ThreadedConnectionPool", real_pool)


def test_get_pool_respects_cooldown(monkeypatch):
    """Within the cooldown window, no new connection attempt is made."""
    import psycopg2.pool as pool_module

    calls = {"n": 0}

    def failing(*args, **kwargs):
        calls["n"] += 1
        raise Exception("connection refused")

    monkeypatch.setattr(pool_module, "ThreadedConnectionPool", failing)
    monkeypatch.setattr(db_module, "POOL_RETRY_SECONDS", 3600)
    db_module._pool = None
    db_module._pool_failed_at = None
    try:
        with pytest.raises(DbUnavailable):
            get_pool()
        with pytest.raises(DbUnavailable):
            get_pool()
        assert calls["n"] == 1  # second call raised from cooldown, no retry
    finally:
        db_module._pool = None
        db_module._pool_failed_at = None


# ── LOG_ROOT (no database needed) ─────────────────────────────────────────

def test_log_root_env_overrides_log_paths():
    """In Docker the host logs live at /host_logs — LOG_ROOT must redirect.

    Runs in a subprocess so the config module is imported fresh with the
    env var set — no importlib.reload pollution of the test process.
    """
    import subprocess
    import sys

    backend_dir = str(Path(__file__).resolve().parent.parent)
    env = dict(os.environ, LOG_ROOT="/host_logs")
    code = (
        "import config; "
        "print(config.LOG_ROOT); "
        "print(config.LINUX_LOG_PATHS['auth']); "
        "print(config.LINUX_LOG_PATHS['apache'])"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, env=env, cwd=backend_dir,
    )
    assert out.returncode == 0, out.stderr
    lines = out.stdout.strip().splitlines()
    assert lines[0] == "/host_logs"
    assert lines[1] == "/host_logs/auth.log"
    assert lines[2] == "/host_logs/apache2/access.log"
