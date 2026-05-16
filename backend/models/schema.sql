-- SecureWatch AI — PostgreSQL Schema
-- Run this once to set up the database:
--   psql -U postgres -d siem_db -f schema.sql

CREATE TABLE IF NOT EXISTS log_sources (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(100) NOT NULL UNIQUE,   -- e.g. 'ssh', 'apache', 'syslog', 'security'
    description TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL PRIMARY KEY,
    source_id   INT REFERENCES log_sources(id) ON DELETE SET NULL,
    source_name VARCHAR(100),                   -- denormalized for fast queries
    timestamp   TIMESTAMPTZ NOT NULL,
    severity    VARCHAR(20)  NOT NULL DEFAULT 'INFO',  -- DEBUG/INFO/WARNING/ERROR/CRITICAL
    message     TEXT         NOT NULL,
    raw_log     TEXT,                           -- original line as-is
    ip_address  VARCHAR(45),                    -- IPv4 or IPv6
    username    VARCHAR(200),
    event_type  VARCHAR(100),                   -- brute_force / port_scan / failed_logon etc.
    extra_data  JSONB DEFAULT '{}',
    host        VARCHAR(255) DEFAULT 'localhost',  -- hostname where event occurred
    os_type     VARCHAR(20)  DEFAULT 'linux',      -- 'windows' | 'linux'
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    id              BIGSERIAL PRIMARY KEY,
    rule_name       VARCHAR(200) NOT NULL,
    severity        VARCHAR(20)  NOT NULL,       -- LOW / MEDIUM / HIGH / CRITICAL
    title           TEXT         NOT NULL,
    description     TEXT,
    ai_explanation  TEXT,                        -- AI plain-English analysis
    related_ips     TEXT[],
    related_users   TEXT[],
    event_count     INT DEFAULT 1,
    is_resolved     BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ
);

-- Indexes for fast dashboard queries
CREATE INDEX IF NOT EXISTS idx_events_timestamp   ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_source      ON events(source_name);
CREATE INDEX IF NOT EXISTS idx_events_severity    ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_ip          ON events(ip_address);
CREATE INDEX IF NOT EXISTS idx_events_host        ON events(host);
CREATE INDEX IF NOT EXISTS idx_events_os_type     ON events(os_type);
CREATE INDEX IF NOT EXISTS idx_alerts_severity    ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_resolved    ON alerts(is_resolved);

-- Seed source types
INSERT INTO log_sources (name, description) VALUES
    ('ssh',        'SSH authentication logs from /var/log/auth.log'),
    ('apache',     'Apache2 access & error logs'),
    ('syslog',     'General system logs from /var/log/syslog'),
    ('auth',       'Linux authentication events'),
    ('kernel',     'Linux kernel events from /var/log/kern.log'),
    ('journald',   'Systemd journal events'),
    ('nginx',      'Nginx access & error logs'),
    ('security',   'Windows Security Event Log'),
    ('system',     'Windows System Event Log'),
    ('defender',   'Windows Defender events'),
    ('powershell', 'Windows PowerShell script execution')
ON CONFLICT (name) DO NOTHING;
