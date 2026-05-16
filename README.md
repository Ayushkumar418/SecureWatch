<div align="center">

# 🛡️ SecureWatch AI

### AI-Powered Real-Time Cross-Platform SIEM Platform

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://python.org)
[![React](https://img.shields.io/badge/React-18+-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)](https://postgresql.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**SecureWatch AI** is an open-source Security Information and Event Management (SIEM) platform that monitors live operating system logs in real-time, detects threats using AI and rule-based engines, and visualizes attacks through a modern cybersecurity dashboard.

[Features](#-features) · [Quick Start](#-quick-start) · [Architecture](#-architecture) · [Screenshots](#-dashboard) · [Configuration](#-configuration)

</div>

---

## ✨ Features

### 🖥️ Cross-Platform Log Collection
| Platform | Sources | Method |
|----------|---------|--------|
| **Windows 10/11/Server** | Security, System, Defender, PowerShell | `wevtutil` (zero deps) |
| **Linux** (Ubuntu, Kali, Fedora, Arch, Debian) | auth.log, syslog, kern.log, Apache/Nginx | File tailing + `journalctl` |
| **WSL / VMs** | All Linux sources | Same as native Linux |

### 🤖 AI-Powered Analysis
- **Google Gemini 2.0 Flash** — primary AI (free tier)
- **Anthropic Claude** — fallback AI
- **Rule-based fallback** — works without any API keys
- Plain-English alert explanations with remediation steps

### 🔍 Advanced Threat Detection
- SSH/RDP brute-force detection (sliding window correlation)
- SQL injection pattern matching
- Suspicious PowerShell activity (encoded commands, AMSI bypass)
- Windows Defender disabled alerts
- New admin account creation
- Service installation (persistence detection)
- HTTP vulnerability scanning
- Account lockout storms

### 🌐 Threat Intelligence
- **VirusTotal** integration — IP reputation scoring
- **AbuseIPDB** integration — abuse confidence scoring
- Local caching (24h TTL) to minimize API calls
- Batch IP lookup support

### ⚡ Real-Time Dashboard
- **WebSocket streaming** — instant event delivery (no polling delay)
- Live attack timeline with auto-updating charts
- Threat Map with ranked IP board + SVG threat rings
- Print-to-PDF security reports
- System health monitoring

---

## 🚀 Quick Start

### Option 1: Docker (Recommended)

```bash
git clone https://github.com/YourUsername/SecureWatch.git
cd SecureWatch
docker-compose up
```

Open **http://localhost:3000** — done!

### Option 2: Manual Installation

#### Prerequisites
- Python 3.10+
- Node.js 18+
- PostgreSQL 14+

#### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
# venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your database credentials and API keys

# Initialize database
psql -U postgres -c "CREATE DATABASE siem_db;"
psql -U postgres -d siem_db -f models/schema.sql

# Start SecureWatch
python main.py                  # Live mode (auto-detects OS)
python main.py --demo           # Demo mode (simulated logs)
```

#### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Configure API endpoint
cp .env.example .env
# Edit .env if backend is on a different host

# Start development server
npm run dev
```

Open **http://localhost:3000**

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    SecureWatch AI Architecture                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │  Windows      │  │  Linux       │  │  Demo        │          │
│  │  Agents       │  │  Agents      │  │  Simulator   │          │
│  │  ─────────    │  │  ─────────   │  │  ─────────   │          │
│  │  Security     │  │  auth.log    │  │  Fake SSH    │          │
│  │  System       │  │  syslog      │  │  Fake HTTP   │          │
│  │  Defender     │  │  kern.log    │  │  Fake Syslog │          │
│  │  PowerShell   │  │  Apache      │  │              │          │
│  │              │  │  journalctl  │  │              │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                 │                 │                    │
│         └────────┬────────┴────────┬────────┘                   │
│                  ▼                 ▼                             │
│         ┌──────────────┐  ┌──────────────────┐                  │
│         │  Normalizer  │  │ Detection Engine │                  │
│         │  Layer       │──│  • Instant Rules  │                  │
│         │              │  │  • Correlator     │                  │
│         └──────┬───────┘  └────────┬─────────┘                  │
│                │                   │                             │
│                ▼                   ▼                             │
│     ┌─────────────────┐  ┌──────────────────┐                   │
│     │   PostgreSQL     │  │  Alert System    │                   │
│     │   Database       │  │  • AI Analyzer   │                   │
│     │                  │  │  • Email Notify  │                   │
│     └────────┬─────────┘  │  • Threat Intel  │                   │
│              │            └────────┬─────────┘                   │
│              ▼                     ▼                             │
│     ┌──────────────────────────────────────┐                    │
│     │        Flask API + Socket.IO          │                    │
│     │        (REST + WebSocket)             │                    │
│     └──────────────────┬───────────────────┘                    │
│                        ▼                                        │
│     ┌──────────────────────────────────────┐                    │
│     │     React Dashboard (Vite)            │                    │
│     │     • Overview    • Alerts            │                    │
│     │     • Live Events • Threat Map        │                    │
│     │     • Reports     • Settings          │                    │
│     └──────────────────────────────────────┘                    │
└─────────────────────────────────────────────────────────────────┘
```

### Project Structure

```
SecureWatch/
├── backend/
│   ├── agents/
│   │   ├── linux/           # Linux log agents (auth, syslog, kern, apache, journald)
│   │   ├── windows/         # Windows agents (security, system, defender, powershell)
│   │   ├── common/          # Shared utilities (file_watcher)
│   │   ├── base.py          # Abstract base agent class
│   │   └── registry.py      # Auto-discovery + OS detection
│   ├── detection/
│   │   ├── engine.py        # Central detection engine
│   │   ├── rules.py         # All detection rules
│   │   └── correlator.py    # Multi-event correlation (brute force, scans)
│   ├── normalizer/          # Unified log normalization layer
│   ├── websocket/           # Socket.IO real-time streaming
│   ├── threat_intel/        # VirusTotal + AbuseIPDB integration
│   ├── ai/                  # AI analysis (Gemini / Claude)
│   ├── api/                 # Flask REST API
│   ├── models/              # Database layer + schema
│   ├── main.py              # Unified entry point
│   └── config.py            # Central configuration + OS detection
├── frontend/
│   ├── src/
│   │   ├── components/      # Reusable UI components
│   │   ├── hooks/           # React hooks (useFetch, useSocket)
│   │   ├── pages/           # Page components (6 pages)
│   │   └── config.js        # Frontend configuration
│   └── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## 🖥️ Dashboard

The dashboard features 6 pages:

| Page | Description |
|------|-------------|
| **Overview** | Stat cards, event timeline, source distribution, severity breakdown, top attacking IPs |
| **Live Events** | Real-time filterable event table with search, source/severity filters, pagination |
| **Alerts** | Expandable alert cards with AI explanations, one-click resolve, severity filtering |
| **Threat Map** | Ranked IP threat board with SVG threat rings, attack vector breakdown |
| **Reports** | Security summary with Print/Export PDF functionality |
| **Settings** | System health, AI status, agent activity, detection rules reference |

---

## ⚙️ Configuration

### Environment Variables

#### Backend (`backend/.env`)

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_HOST` | PostgreSQL host | `localhost` |
| `DB_PORT` | PostgreSQL port | `5432` |
| `DB_NAME` | Database name | `siem_db` |
| `DB_USER` | Database user | `siem_user` |
| `DB_PASSWORD` | Database password | `siem_pass` |
| `PORT` | API server port | `5000` |
| `DASHBOARD_URL` | Frontend URL (for email links) | `http://localhost:3000` |
| `GEMINI_API_KEY` | Google Gemini AI key | — |
| `ANTHROPIC_API_KEY` | Anthropic Claude key | — |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | — |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key | — |
| `SMTP_USER` | Gmail address for alerts | — |
| `SMTP_PASS` | Gmail app password | — |
| `SIEM_DEMO_MODE` | `true` for simulated logs | `false` |

#### Frontend (`frontend/.env`)

| Variable | Description | Default |
|----------|-------------|---------|
| `VITE_API_URL` | Backend API URL | `http://localhost:5000/api` |

---

## 🔒 Detection Rules

### Instant Rules (fire on single event)
| Rule | Severity | Source |
|------|----------|--------|
| SQL Injection Attempt | CRITICAL | Apache/Nginx |
| Sensitive Path Access | HIGH | Apache/Nginx |
| Root SSH Login | CRITICAL | auth.log |
| New User Account Created | HIGH | syslog |
| OOM Kill | MEDIUM | syslog |
| Windows Defender Disabled | CRITICAL | Defender |
| Malware Detected | CRITICAL | Defender |
| User Added to Admin Group | CRITICAL | Security |
| New Service Installed | HIGH | System |
| Suspicious PowerShell | HIGH | PowerShell |

### Correlation Rules (fire on N events in time window)
| Rule | Threshold | Window | Severity |
|------|-----------|--------|----------|
| SSH Brute Force | 5 failures | 120s | CRITICAL |
| RDP Brute Force | 5 failures | 120s | CRITICAL |
| HTTP Scanning | 20 × 4xx | 30s | HIGH |
| Account Lockout Storm | 3 lockouts | 300s | HIGH |

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check + DB status |
| `GET` | `/api/stats` | Dashboard summary statistics |
| `GET` | `/api/events` | List events (filterable, paginated) |
| `GET` | `/api/events/:id` | Single event detail |
| `GET` | `/api/alerts` | List alerts (filterable) |
| `GET` | `/api/alerts/:id` | Single alert with AI explanation |
| `POST` | `/api/alerts/:id/resolve` | Resolve an alert |
| `POST` | `/api/alerts/:id/analyze` | Trigger AI analysis |
| `GET` | `/api/ai-status` | AI analyzer status |
| `GET` | `/api/threat-intel/:ip` | Threat intel lookup for IP |
| `POST` | `/api/threat-intel/batch` | Batch IP lookup |
| `GET` | `/api/threat-intel/status` | Provider status |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built with ❤️ for the cybersecurity community**

SecureWatch AI · Real-Time · Cross-Platform · AI-Powered

</div>
