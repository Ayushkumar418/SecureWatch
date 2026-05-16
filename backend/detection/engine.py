"""
engine.py -- Central detection engine.

All normalized events pass through this engine. It evaluates each event
against all active detection rules, fires alerts when rules trigger,
and feeds the correlator for multi-event pattern detection.
"""
import logging
from datetime import datetime, timezone

log = logging.getLogger("detection.engine")

_engine_instance = None
_db_available = None  # None = not checked yet, True/False after first attempt


def _check_db():
    """Check if database is available (cached after first attempt)."""
    global _db_available
    if _db_available is not None:
        return _db_available
    try:
        from models.db import insert_alert
        _db_available = True
    except Exception:
        _db_available = False
    return _db_available


def get_engine():
    """Get the singleton detection engine instance."""
    global _engine_instance
    return _engine_instance


class DetectionEngine:
    """
    Central detection engine that processes all incoming events.
    """

    def __init__(self):
        global _engine_instance

        from detection.rules import get_all_rules
        from detection.correlator import EventCorrelator

        self.rules = get_all_rules()
        self.correlator = EventCorrelator()
        self._alert_callback = None
        self._db_warned = False

        _engine_instance = self
        log.info("Detection engine initialized with %d rules", len(self.rules))

    def set_alert_callback(self, callback):
        """Set a callback function for new alerts (e.g., WebSocket broadcast)."""
        self._alert_callback = callback

    def check(self, event: dict):
        """
        Process an event through all detection rules and the correlator.
        Called by BaseAgent.emit_event() for every incoming event.
        """
        try:
            # 1. Check instant rules (SQLi, malware, etc.)
            for rule in self.rules:
                if rule.matches(event):
                    alert = rule.fire(event)
                    if alert:
                        self._create_alert(alert)

            # 2. Feed into correlator for time-window rules (brute force, etc.)
            corr_alerts = self.correlator.process(event)
            for alert in corr_alerts:
                self._create_alert(alert)

        except Exception as e:
            log.error("Detection engine error: %s", e, exc_info=True)

    def _create_alert(self, alert_data: dict):
        """Insert alert into DB (if available) and notify via callback."""
        alert_id = None

        # Try DB insert -- fall back to in-memory store
        try:
            from models.db import insert_alert
            alert_id = insert_alert(
                rule_name=alert_data["rule_name"],
                severity=alert_data["severity"],
                title=alert_data["title"],
                description=alert_data.get("description"),
                related_ips=alert_data.get("related_ips", []),
                related_users=alert_data.get("related_users", []),
                event_count=alert_data.get("event_count", 1),
            )
        except Exception:
            # Use in-memory store
            try:
                from models.mem_store import insert_alert as mem_insert_alert
                alert_id = mem_insert_alert(
                    rule_name=alert_data["rule_name"],
                    severity=alert_data["severity"],
                    title=alert_data["title"],
                    description=alert_data.get("description"),
                    related_ips=alert_data.get("related_ips", []),
                    related_users=alert_data.get("related_users", []),
                    event_count=alert_data.get("event_count", 1),
                )
            except Exception:
                pass

        log.warning(
            "ALERT [%s] %s -- %s",
            alert_data["severity"],
            alert_data["rule_name"], alert_data["title"]
        )

        if self._alert_callback:
            alert_data["id"] = alert_id
            self._alert_callback(alert_data)
