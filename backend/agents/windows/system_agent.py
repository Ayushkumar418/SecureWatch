"""
system_agent.py — Monitors Windows System Event Log.

Key Event IDs:
  7045 — Service installed (potential persistence)
  7040 — Service start type changed
  1074 — System shutdown/restart
  6005 — Event Log service started
  6006 — Event Log service stopped
  41   — Unexpected shutdown (kernel power)
  6008 — Unexpected shutdown (previous)
"""
import subprocess
import xml.etree.ElementTree as ET
import logging
import time
from datetime import datetime, timezone

from agents.base import BaseAgent
import config

log = logging.getLogger("agent.win_system")

INTERESTING_IDS = {7045, 7040, 1074, 6005, 6006, 41, 6008}

SEVERITY_MAP = {
    7045: "HIGH", 7040: "WARNING", 1074: "INFO",
    6005: "INFO", 6006: "WARNING", 41: "WARNING", 6008: "WARNING",
}

EVENT_NAMES = {
    7045: "service_installed", 7040: "service_config_change",
    1074: "system_shutdown", 6005: "eventlog_start",
    6006: "eventlog_stop", 41: "unexpected_shutdown",
    6008: "unexpected_shutdown_prev",
}

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


class WindowsSystemAgent(BaseAgent):
    name = "win_system_agent"
    source_name = "system"
    os_type = "windows"

    def __init__(self):
        super().__init__()
        self._last_record_id = 0

    def collect(self):
        self.logger.info("Monitoring Windows System Event Log")
        while self._running:
            try:
                events = self._query_events()
                for ev in events:
                    if not self._running:
                        break
                    self.emit_event(ev)
            except Exception as e:
                self.logger.error("Error querying System log: %s", e)
            time.sleep(config.TAIL_SLEEP * 2)

    def _query_events(self) -> list[dict]:
        try:
            result = subprocess.run(
                ["wevtutil", "qe", "System", "/c:25", "/f:xml", "/rd:true"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return []
            return self._parse_events(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def _parse_events(self, xml_text: str) -> list[dict]:
        events = []
        try:
            root = ET.fromstring(f"<Events>{xml_text}</Events>")
        except ET.ParseError:
            return []

        for ev in root.findall(".//e:Event", NS):
            try:
                parsed = self._parse_one(ev)
                if parsed:
                    events.append(parsed)
            except Exception:
                continue
        return events

    def _parse_one(self, ev_elem) -> dict | None:
        sys_elem = ev_elem.find("e:System", NS)
        if sys_elem is None:
            return None

        eid_elem = sys_elem.find("e:EventID", NS)
        if eid_elem is None:
            return None
        eid = int(eid_elem.text)
        if eid not in INTERESTING_IDS:
            return None

        rec_elem = sys_elem.find("e:EventRecordID", NS)
        if rec_elem is not None:
            rid = int(rec_elem.text)
            if rid <= self._last_record_id:
                return None
            self._last_record_id = rid

        time_elem = sys_elem.find("e:TimeCreated", NS)
        ts = datetime.now(timezone.utc)
        if time_elem is not None:
            try:
                ts = datetime.fromisoformat(time_elem.get("SystemTime", "").replace("Z", "+00:00"))
            except ValueError:
                pass

        data = {}
        for d in (ev_elem.find("e:EventData", NS) or []):
            name = d.get("Name", "")
            if name:
                data[name] = d.text or ""

        severity = SEVERITY_MAP.get(eid, "INFO")
        event_type = EVENT_NAMES.get(eid, f"system_{eid}")
        msg = f"[EID:{eid}] {event_type.replace('_', ' ').title()}"
        if data.get("ServiceName"):
            msg += f" — Service: {data['ServiceName']}"

        return {
            "source_name": self.source_name,
            "timestamp": ts,
            "severity": severity,
            "event_type": event_type,
            "message": msg,
            "raw_log": ET.tostring(ev_elem, encoding="unicode")[:1000],
            "host": config.HOSTNAME,
            "os_type": self.os_type,
            "extra_data": {"event_id": eid, **data},
        }
