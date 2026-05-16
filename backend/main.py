"""
main.py — SecureWatch AI unified entry point.

Replaces the old start_siem.py with:
  • Automatic OS detection
  • Agent auto-discovery via registry
  • Central detection engine
  • WebSocket real-time streaming
  • AI analyzer (optional)
  • Email notifier (optional)
  • Flask API server

Usage:
  python main.py              # live mode — auto-detects OS, real logs
  python main.py --demo       # demo mode — simulated logs (for testing)

Stop with Ctrl+C — all services shut down cleanly.
"""
import os
import sys
import time
import logging
import argparse
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent))

import config
from config import print_config_summary

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("SecureWatch")

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗          ║
║   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝          ║
║   ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗            ║
║   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝            ║
║   ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗          ║
║   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝          ║
║                                                              ║
║   ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗                ║
║   ██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║                ║
║   ██║ █╗ ██║███████║   ██║   ██║     ███████║                ║
║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║                ║
║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║                ║
║    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝                ║
║                                                              ║
║   AI-Powered Real-Time Cross-Platform SIEM                   ║
║   v3.0                                                       ║
╚══════════════════════════════════════════════════════════════╝
"""


def parse_args():
    parser = argparse.ArgumentParser(description="SecureWatch AI — SIEM Platform")
    parser.add_argument("--demo", action="store_true", help="Run in demo mode with simulated logs")
    parser.add_argument("--port", type=int, default=None, help="API server port (default: 5000)")
    return parser.parse_args()


def main():
    args = parse_args()
    print(BANNER)

    # Apply CLI overrides
    if args.demo:
        config.DEMO_MODE = True
    if args.port:
        config.API_PORT = args.port

    print_config_summary()

    # ── 1. Database migration ─────────────────────────────────────────
    log.info("═══ Database ═══")
    try:
        from models.db import ensure_schema
        ensure_schema()
        log.info("  ✅ Database connected & schema up to date")
    except Exception as e:
        log.error("  ❌ Database connection failed: %s", e)
        log.error("     Make sure PostgreSQL is running and .env is configured.")
        sys.exit(1)

    # ── 2. Detection engine ───────────────────────────────────────────
    log.info("═══ Detection Engine ═══")
    from detection.engine import DetectionEngine
    engine = DetectionEngine()
    log.info("  ✅ Detection engine ready (%d rules loaded)", len(engine.rules))

    # ── 3. Flask API + WebSocket ──────────────────────────────────────
    log.info("═══ API Server ═══")
    from api.app import app

    # Register threat intel routes
    try:
        from api.threat_routes import threat_bp
        app.register_blueprint(threat_bp)
        log.info("  ✅ Threat intelligence routes registered")
    except Exception as e:
        log.warning("  ⬚ Threat intel routes not loaded: %s", e)

    # Initialize WebSocket
    socketio = None
    try:
        from websocket.server import init_websocket, broadcast_alert
        socketio = init_websocket(app)
        if socketio:
            engine.set_alert_callback(broadcast_alert)
    except ImportError:
        log.warning("  ⬚ flask-socketio not installed — using HTTP polling")

    # ── 4. Discover & start agents ────────────────────────────────────
    log.info("═══ Log Agents ═══")

    if config.DEMO_MODE:
        # Start log simulator in background
        log.info("  🎭 Starting log simulator (demo mode)...")
        import threading
        from simulate_logs import run_simulator
        sim_thread = threading.Thread(target=run_simulator, daemon=True, name="simulator")
        sim_thread.start()
        time.sleep(1)  # let simulator create files

    from agents.registry import get_agents
    agents = get_agents()
    for agent in agents:
        agent.start()
    log.info("  ✅ %d agent(s) started", len(agents))

    # ── 5. AI analyzer (optional) ─────────────────────────────────────
    log.info("═══ AI Analyzer ═══")
    gemini_ok = config.GEMINI_API_KEY and "your" not in config.GEMINI_API_KEY
    anthropic_ok = config.ANTHROPIC_API_KEY and "your" not in config.ANTHROPIC_API_KEY
    if gemini_ok or anthropic_ok:
        try:
            import threading
            from ai_analyzer import run as run_ai
            ai_thread = threading.Thread(target=run_ai, daemon=True, name="ai_analyzer")
            ai_thread.start()
            log.info("  ✅ AI analyzer started (%s)",
                     "Gemini" if gemini_ok else "Anthropic")
        except Exception as e:
            log.warning("  ⬚ AI analyzer failed to start: %s", e)
    else:
        log.info("  ⬚ No AI keys configured — rule-based analysis only")

    # ── 6. Email notifier (optional) ──────────────────────────────────
    log.info("═══ Email Notifier ═══")
    if config.SMTP_USER and "your" not in config.SMTP_USER:
        try:
            import threading
            from email_notifier import run as run_email
            email_thread = threading.Thread(target=run_email, daemon=True, name="email_notifier")
            email_thread.start()
            log.info("  ✅ Email notifier started")
        except Exception as e:
            log.warning("  ⬚ Email notifier failed: %s", e)
    else:
        log.info("  ⬚ SMTP not configured — email alerts disabled")

    # ── 7. Threat intelligence ────────────────────────────────────────
    log.info("═══ Threat Intelligence ═══")
    if config.VIRUSTOTAL_API_KEY or config.ABUSEIPDB_API_KEY:
        try:
            from threat_intel.manager import ThreatIntelManager
            ti = ThreatIntelManager()
            log.info("  ✅ Threat intel ready (%d providers)", len(ti.providers))
        except Exception as e:
            log.warning("  ⬚ Threat intel failed: %s", e)
    else:
        log.info("  ⬚ No threat intel API keys — enrichment disabled")

    # ── 8. Start server ───────────────────────────────────────────────
    log.info("")
    log.info("══════════════════════════════════════════════════════")
    log.info("  🌐 Dashboard:   %s", config.DASHBOARD_URL)
    log.info("  🔌 API:         http://%s:%d/api", config.API_HOST, config.API_PORT)
    log.info("  📡 WebSocket:   %s", "Enabled" if socketio else "Disabled (polling)")
    log.info("  🖥️  OS:          %s (%s)", config.OS_TYPE, config.OS_RELEASE)
    log.info("  🎭 Mode:        %s", "DEMO" if config.DEMO_MODE else "LIVE")
    log.info("══════════════════════════════════════════════════════")
    log.info("  Press Ctrl+C to stop all services.")
    log.info("")

    try:
        if socketio:
            socketio.run(app, host=config.API_HOST, port=config.API_PORT,
                         debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
        else:
            app.run(host=config.API_HOST, port=config.API_PORT,
                    debug=False, use_reloader=False)
    except KeyboardInterrupt:
        log.info("Shutting down SecureWatch...")
        for agent in agents:
            agent.stop()


if __name__ == "__main__":
    main()
