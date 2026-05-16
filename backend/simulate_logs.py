"""
simulate_logs.py — Generates fake log lines for testing WITHOUT needing
                   real Linux log files.

Creates 3 temporary files and writes realistic log lines into them,
so you can test all agents on Windows / Mac / a fresh VM.

Usage:
  python simulate_logs.py

The script writes logs indefinitely. Open another terminal and run
the agents + API against these fake files.
"""
import os
import sys
import time
import random
import threading
from datetime import datetime, timezone
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────
SIM_DIR     = Path("/tmp/siem_sim_logs")
AUTH_FILE   = SIM_DIR / "auth.log"
APACHE_FILE = SIM_DIR / "access.log"
SYSLOG_FILE = SIM_DIR / "syslog"

ATTACKER_IPS  = ["192.168.1.50", "10.0.0.99", "45.33.32.156"]
LEGIT_IPS     = ["192.168.1.10", "192.168.1.20", "127.0.0.1"]
USERS         = ["root", "admin", "ubuntu", "pi", "test"]

SIM_DIR.mkdir(parents=True, exist_ok=True)

# Patch agents to use these files instead of real system paths
import importlib
import agents.ssh_agent    as ssh_mod
import agents.apache_agent as apache_mod
import agents.syslog_agent as syslog_mod

ssh_mod.LOG_FILE    = AUTH_FILE
apache_mod.LOG_FILE = APACHE_FILE
syslog_mod.LOG_FILE = SYSLOG_FILE


# ── Helpers ───────────────────────────────────────────────────────────────

def now_str():
    return datetime.now().strftime("%b %d %H:%M:%S")

def write(path: Path, line: str):
    with open(path, "a") as f:
        f.write(line + "\n")


# ── SSH simulators ────────────────────────────────────────────────────────

def sim_ssh_brute_force():
    """Write 8 rapid failed logins from a single attacker IP."""
    ip   = random.choice(ATTACKER_IPS)
    user = random.choice(USERS)
    print(f"[sim] SSH BRUTE FORCE from {ip} targeting {user}")
    for _ in range(8):
        write(AUTH_FILE,
              f"{now_str()} myserver sshd[1234]: Failed password for {user} from {ip} port 54321 ssh2")
        time.sleep(0.3)

def sim_ssh_success():
    ip   = random.choice(LEGIT_IPS)
    user = "ubuntu"
    print(f"[sim] SSH Success: {user} from {ip}")
    write(AUTH_FILE,
          f"{now_str()} myserver sshd[1234]: Accepted password for {user} from {ip} port 22 ssh2")

def sim_ssh_invalid():
    ip   = random.choice(ATTACKER_IPS)
    write(AUTH_FILE,
          f"{now_str()} myserver sshd[1234]: Invalid user hacker from {ip} port 54321")


# ── Apache simulators ─────────────────────────────────────────────────────

def sim_apache_normal():
    ip   = random.choice(LEGIT_IPS)
    paths = ["/", "/index.html", "/about", "/contact", "/api/data"]
    path  = random.choice(paths)
    write(APACHE_FILE,
          f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
          f'"GET {path} HTTP/1.1" 200 1234 "-" "Mozilla/5.0"')

def sim_apache_scan():
    ip    = random.choice(ATTACKER_IPS)
    paths = ["/admin", "/.env", "/wp-login.php", "/phpmyadmin", "/.git/config",
             "/backup.zip", "/config.php", "/shell.php"]
    print(f"[sim] HTTP SCAN from {ip}")
    for path in paths:
        write(APACHE_FILE,
              f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
              f'"GET {path} HTTP/1.1" 404 0 "-" "sqlmap/1.0"')
        time.sleep(0.1)

def sim_apache_sqli():
    ip = random.choice(ATTACKER_IPS)
    path = "/search?q=1' OR 1=1--&id=UNION SELECT * FROM users"
    print(f"[sim] SQL INJECTION ATTEMPT from {ip}")
    write(APACHE_FILE,
          f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
          f'"GET {path} HTTP/1.1" 200 500 "-" "python-requests"')


# ── Syslog simulators ─────────────────────────────────────────────────────

def sim_syslog_sudo():
    user = random.choice(["ubuntu", "pi"])
    write(SYSLOG_FILE,
          f"{now_str()} myserver sudo: {user} : TTY=pts/0 ; "
          f"COMMAND=/usr/bin/apt install netcat")

def sim_syslog_new_user():
    print("[sim] NEW USER CREATED — potential persistence!")
    write(SYSLOG_FILE,
          f"{now_str()} myserver useradd[5678]: new user: name=backdoor,"
          f"UID=1002,GID=1002,home=/home/backdoor,shell=/bin/bash")

def sim_syslog_oom():
    write(SYSLOG_FILE,
          f"{now_str()} myserver kernel: Out of memory: Kill process 9999 (python3) "
          f"score 900 or sacrifice child")


# ── Scenario runner ───────────────────────────────────────────────────────

SCENARIOS = [
    (sim_ssh_success,      5),    # weight: how often this fires
    (sim_ssh_invalid,      3),
    (sim_ssh_brute_force,  1),
    (sim_apache_normal,    8),
    (sim_apache_scan,      1),
    (sim_apache_sqli,      1),
    (sim_syslog_sudo,      4),
    (sim_syslog_new_user,  1),
    (sim_syslog_oom,       1),
]

def random_scenario():
    fns, weights = zip(*SCENARIOS)
    return random.choices(fns, weights=weights, k=1)[0]


def run_simulator():
    print(f"Log simulator writing to {SIM_DIR}")
    print("  auth.log  ->", AUTH_FILE)
    print("  access.log->", APACHE_FILE)
    print("  syslog    ->", SYSLOG_FILE)
    print("Press Ctrl+C to stop.\n")
    while True:
        scenario = random_scenario()
        scenario()
        time.sleep(random.uniform(0.5, 2.5))


def run_agents_in_background():
    """Start all agents watching the simulated log files."""
    sys.path.insert(0, str(Path(__file__).parent))
    from run_agents import start_agent, AGENTS
    for name, fn in AGENTS:
        start_agent(name, fn)


if __name__ == "__main__":
    # Start agents in background threads
    run_agents_in_background()
    time.sleep(1)   # let agents open files first
    # Run simulator in main thread
    try:
        run_simulator()
    except KeyboardInterrupt:
        print("\nSimulator stopped.")
