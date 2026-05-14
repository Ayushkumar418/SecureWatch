# SIEM Backend — Phase 2 Setup Guide

## Folder Structure

```
backend/
├── agents/
│   ├── ssh_agent.py        ← watches auth.log  (SSH brute force)
│   ├── apache_agent.py     ← watches access.log (scans, SQLi)
│   └── syslog_agent.py     ← watches syslog (sudo, new users, OOM)
├── api/
│   └── app.py              ← Flask REST API  (port 5000)
├── models/
│   ├── db.py               ← PostgreSQL connection + helpers
│   └── schema.sql          ← run once to create tables
├── run_agents.py           ← starts all 3 agents together
├── simulate_logs.py        ← TEST MODE — no real logs needed!
├── requirements.txt
└── .env.example            ← copy to .env and fill in values
```

---

## Step 1 — Install PostgreSQL

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install postgresql postgresql-contrib -y
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql <<EOF
CREATE USER siem_user WITH PASSWORD 'siem_pass';
CREATE DATABASE siem_db OWNER siem_user;
GRANT ALL PRIVILEGES ON DATABASE siem_db TO siem_user;
EOF
```

---

## Step 2 — Create the tables

```bash
psql -U siem_user -d siem_db -f models/schema.sql
# Enter password: siem_pass
```

Verify tables were created:
```bash
psql -U siem_user -d siem_db -c "\dt"
```

---

## Step 3 — Install Python dependencies

```bash
cd backend/
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

---

## Step 4 — Configure environment

```bash
cp .env.example .env
nano .env        # Edit DB_PASS and other settings
```

---

## Step 5A — Run in TEST MODE (recommended first)

This works on any OS — no real Linux log files needed:

```bash
# Terminal 1: run simulator + agents together
python simulate_logs.py

# Terminal 2: run the API
python api/app.py
```

Then open: http://localhost:5000/api/stats
You should see live data!

---

## Step 5B — Run on a REAL Linux server

```bash
# Terminal 1: run all 3 agents (needs sudo for /var/log access)
sudo python run_agents.py

# Terminal 2: run the API
python api/app.py
```

---

## Step 6 — Test the API

```bash
# Check health
curl http://localhost:5000/api/health

# See dashboard stats
curl http://localhost:5000/api/stats | python3 -m json.tool

# See latest events
curl "http://localhost:5000/api/events?limit=10" | python3 -m json.tool

# See alerts
curl http://localhost:5000/api/alerts | python3 -m json.tool

# Resolve an alert (replace 1 with actual alert ID)
curl -X POST http://localhost:5000/api/alerts/1/resolve
```

---

## API Endpoints Summary

| Method | Endpoint                      | Description                    |
|--------|-------------------------------|--------------------------------|
| GET    | /api/health                   | Health check                   |
| GET    | /api/events                   | List events (filterable)       |
| GET    | /api/events/:id               | Single event detail            |
| GET    | /api/alerts                   | List alerts                    |
| POST   | /api/alerts/:id/resolve       | Mark alert as resolved         |
| GET    | /api/stats                    | Dashboard summary numbers      |

### Event filter query params:
- `?source=ssh` — filter by source
- `?severity=CRITICAL` — filter by severity
- `?search=192.168.1` — text search
- `?limit=50&offset=100` — pagination

---

## What gets detected

| Agent         | Attack type              | Alert severity |
|---------------|--------------------------|----------------|
| ssh_agent     | SSH brute force          | CRITICAL       |
| ssh_agent     | Invalid user attempts    | WARNING        |
| apache_agent  | HTTP path scanning       | HIGH           |
| apache_agent  | SQL injection attempt    | CRITICAL       |
| apache_agent  | Sensitive path access    | HIGH           |
| syslog_agent  | New user created         | HIGH           |
| syslog_agent  | Root login via SSH       | CRITICAL       |
| syslog_agent  | Password changed         | MEDIUM         |
| syslog_agent  | OOM kill                 | MEDIUM         |

---

## Next Steps (Phase 3)

- Add `ANTHROPIC_API_KEY` to `.env`
- Build `ai_analyzer.py` — sends alert details to Claude API
  and gets a plain-English threat explanation
- Add email notifications via SMTP
