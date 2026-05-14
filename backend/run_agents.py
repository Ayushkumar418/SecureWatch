"""
run_agents.py — Starts all log collection agents in parallel threads.

Usage:
  python run_agents.py

Each agent runs in its own daemon thread.
Press Ctrl+C to stop all agents.
"""
import sys
import time
import logging
import threading
from pathlib import Path

# Make sure project root is on the path
sys.path.insert(0, str(Path(__file__).parent))

from agents.ssh_agent    import run as run_ssh
from agents.apache_agent import run as run_apache
from agents.syslog_agent import run as run_syslog

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [runner] %(levelname)s %(message)s"
)
log = logging.getLogger("runner")

AGENTS = [
    ("ssh_agent",    run_ssh),
    ("apache_agent", run_apache),
    ("syslog_agent", run_syslog),
]


def start_agent(name, fn):
    def target():
        try:
            log.info("Starting %s …", name)
            fn()
        except FileNotFoundError as e:
            log.warning("%s could not start (file not found): %s", name, e)
        except Exception as e:
            log.error("%s crashed: %s", name, e, exc_info=True)

    t = threading.Thread(target=target, name=name, daemon=True)
    t.start()
    return t


def main():
    log.info("=" * 50)
    log.info("  SIEM — Log Collection Agents Starting")
    log.info("=" * 50)

    threads = [start_agent(name, fn) for name, fn in AGENTS]

    log.info("%d agents running. Press Ctrl+C to stop.", len(threads))
    try:
        while True:
            time.sleep(5)
            alive = [t.name for t in threads if t.is_alive()]
            dead  = [t.name for t in threads if not t.is_alive()]
            if dead:
                log.warning("Dead agents: %s", dead)
    except KeyboardInterrupt:
        log.info("Shutting down …")


if __name__ == "__main__":
    main()
