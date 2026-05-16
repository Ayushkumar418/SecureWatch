"""
engine.py — Central detection engine.

All normalized events pass through this engine. It evaluates each event
against all active detection rules, fires alerts when rules trigger,
and feeds the correlator for multi-event pattern detection.
"""
import logging
from datetime import datetime, timezone

from models.db import insert_alert

log = logging.getLogger("detection.engine")

_engine_instance = None


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
        """Insert alert into DB and notify via callback."""
        try:
            alert_id = insert_alert(
                rule_name=alert_data["rule_name"],
                severity=alert_data["severity"],
                title=alert_data["title"],
                description=alert_data.get("description"),
                related_ips=alert_data.get("related_ips", []),
                related_users=alert_data.get("related_users", []),
                event_count=alert_data.get("event_count", 1),
            )
            log.warning(
                "🚨 ALERT #%s [%s] %s — %s",
                alert_id, alert_data["severity"],
                alert_data["rule_name"], alert_data["title"]
            )

            if self._alert_callback:
                alert_data["id"] = alert_id
                self._alert_callback(alert_data)

        except Exception as e:
            log.error("Failed to create alert: %s", e)
