"""
defender_agent.py — Monitors Windows Defender event log.

Channel: Microsoft-Windows-Windows Defender/Operational

Key Event IDs:
  1116 — Malware detected
  1117 — Action taken on malware
  5001 — Real-time protection disabled
  5010 — Scanning disabled
  5012 — Virus scanning disabled
  2001 — Signature update failed
"""
import subprocess
import xml.etree.ElementTree as ET
import logging
import time
from datetime import datetime, timezone

from agents.base import BaseAgent
import config

log = logging.getLogger("agent.win_defender")

INTERESTING_IDS = {1116, 1117, 5001, 5010, 5012, 2001}

SEVERITY_MAP = {
    1116: "CRITICAL", 1117: "HIGH", 5001: "CRITICAL",
    5010: "HIGH", 5012: "HIGH", 2001: "WARNING",
}

EVENT_NAMES = {
    1116: "malware_detected", 1117: "malware_action_taken",
    5001: "realtime_protection_disabled", 5010: "scanning_disabled",
    5012: "virus_scanning_disabled", 2001: "signature_update_failed",
}

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
CHANNEL = "Microsoft-Windows-Windows Defender/Operational"


class WindowsDefenderAgent(BaseAgent):
    name = "win_defender_agent"
    source_name = "defender"
    os_type = "windows"

    def __init__(self):
        super().__init__()
        self._last_record_id = 0

    def collect(self):
        self.logger.info("Monitoring Windows Defender events")
        while self._running:
            try:
                events = self._query_events()
                for ev in events:
                    if not self._running:
                        break
                    self.emit_event(ev)
            except Exception as e:
                self.logger.error("Error querying Defender log: %s", e)
            time.sleep(config.TAIL_SLEEP * 3)

    def _query_events(self) -> list[dict]:
        try:
            result = subprocess.run(
                ["wevtutil", "qe", CHANNEL, "/c:20", "/f:xml", "/rd:true"],
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

        severity = SEVERITY_MAP.get(eid, "INFO")
        event_type = EVENT_NAMES.get(eid, f"defender_{eid}")
        msg = f"[Defender EID:{eid}] {event_type.replace('_', ' ').title()}"

        return {
            "source_name": self.source_name,
            "timestamp": ts,
            "severity": severity,
            "event_type": event_type,
            "message": msg,
            "raw_log": ET.tostring(ev_elem, encoding="unicode")[:1000],
            "host": config.HOSTNAME,
            "os_type": self.os_type,
            "extra_data": {"event_id": eid},
        }
