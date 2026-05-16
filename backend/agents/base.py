"""
base.py — Abstract base class for all log collection agents.

Every agent (Linux or Windows) inherits from BaseAgent and implements:
  - collect()  — the main collection loop
  - parse()    — converts raw log lines into NormalizedEvent dicts
"""
import abc
import logging
import threading
from datetime import datetime, timezone


class BaseAgent(abc.ABC):
    """Abstract base class for all SIEM log agents."""

    name: str = "base_agent"
    source_name: str = "unknown"
    os_type: str = "unknown"

    def __init__(self):
        self.logger = logging.getLogger(f"agent.{self.name}")
        self._running = False
        self._thread = None

    # ── Public API ────────────────────────────────────────────────────────

    def start(self):
        """Start the agent in a background daemon thread."""
        if self._running:
            self.logger.warning("%s is already running", self.name)
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop,
            name=self.name,
            daemon=True,
        )
        self._thread.start()
        self.logger.info("✅ %s started", self.name)

    def stop(self):
        """Signal the agent to stop."""
        self._running = False
        self.logger.info("⏹  %s stopping", self.name)

    def is_alive(self):
        """Check if the agent thread is still running."""
        return self._thread is not None and self._thread.is_alive()

    # ── Override these ────────────────────────────────────────────────────

    @abc.abstractmethod
    def collect(self):
        """
        Main collection loop. Must yield NormalizedEvent dicts.
        This runs continuously — use `self._running` to check for stop signal.
        """
        ...

    # ── Internal ──────────────────────────────────────────────────────────

    def _run_loop(self):
        """Wraps collect() with error handling."""
        try:
            self.collect()
        except Exception as e:
            self.logger.error("%s crashed: %s", self.name, e, exc_info=True)
        finally:
            self._running = False

    def emit_event(self, normalized: dict):
        """
        Insert a normalized event into the DB and broadcast via WebSocket.
        Called by agents after parsing a raw log line.
        """
        from models.db import insert_event

        # Ensure required fields
        normalized.setdefault("host", "")
        normalized.setdefault("os_type", self.os_type)
        normalized.setdefault("source_name", self.source_name)

        try:
            event_id = insert_event(
                source_name=normalized["source_name"],
                timestamp=normalized.get("timestamp", datetime.now(timezone.utc)),
                severity=normalized.get("severity", "INFO"),
                message=normalized.get("message", ""),
                raw_log=normalized.get("raw_log"),
                ip_address=normalized.get("ip_address"),
                username=normalized.get("username"),
                event_type=normalized.get("event_type"),
                extra_data=normalized.get("extra_data"),
                host=normalized.get("host"),
                os_type=normalized.get("os_type"),
            )

            # Broadcast to WebSocket (if available)
            try:
                from websocket.server import broadcast_event
                normalized["id"] = event_id
                broadcast_event(normalized)
            except ImportError:
                pass

            # Feed into detection engine
            try:
                from detection.engine import get_engine
                engine = get_engine()
                if engine:
                    engine.check(normalized)
            except ImportError:
                pass

            return event_id

        except Exception as e:
            self.logger.error("Failed to emit event: %s", e)
            return None
