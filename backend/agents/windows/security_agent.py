"""
security_agent.py — Monitors Windows Security Event Log.

Uses wevtutil (built into all Windows versions, zero dependencies) to
subscribe to Security events in real-time.

Key Event IDs:
  4625 — Failed logon
  4624 — Successful logon
  4648 — Logon with explicit credentials
  4720 — User account created
  4722 — User account enabled
  4732 — Member added to security-enabled group (admin escalation)
  4740 — Account locked out
  4672 — Special privileges assigned (admin logon)
"""
import subprocess
import xml.etree.ElementTree as ET
import logging
import time
from datetime import datetime, timezone

from agents.base import BaseAgent
import config

log = logging.getLogger("agent.win_security")

INTERESTING_IDS = {4624, 4625, 4648, 4720, 4722, 4732, 4740, 4672}

SEVERITY_MAP = {
    4625: "WARNING", 4624: "INFO", 4648: "WARNING",
    4720: "HIGH", 4722: "WARNING", 4732: "CRITICAL",
    4740: "HIGH", 4672: "WARNING",
}

EVENT_NAMES = {
    4625: "failed_logon", 4624: "successful_logon",
    4648: "explicit_credential", 4720: "user_created",
    4722: "user_enabled", 4732: "admin_group_change",
    4740: "account_lockout", 4672: "admin_logon",
}

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


class WindowsSecurityAgent(BaseAgent):
    name = "win_security_agent"
    source_name = "security"
    os_type = "windows"

    def __init__(self):
        super().__init__()
        self._last_record_id = 0

    def collect(self):
        """Poll Windows Security event log for new events."""
        self.logger.info("Monitoring Windows Security Event Log")

        while self._running:
            try:
                events = self._query_recent_events()
                for event in events:
                    if not self._running:
                        break
                    self.emit_event(event)
            except Exception as e:
                self.logger.error("Error querying Security log: %s", e)

            time.sleep(config.TAIL_SLEEP * 2)

    def _query_recent_events(self) -> list[dict]:
        """Query recent Security events using wevtutil."""
        try:
            result = subprocess.run(
                [
                    "wevtutil", "qe", "Security",
                    "/c:25",        # last 25 events
                    "/f:xml",       # XML format
                    "/rd:true",     # most recent first
                ],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return []

            return self._parse_xml_events(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.warning("wevtutil failed: %s", e)
            return []

    def _parse_xml_events(self, xml_text: str) -> list[dict]:
        """Parse wevtutil XML output into normalized events."""
        events = []
        # Wrap in root element for valid XML
        wrapped = f"<Events>{xml_text}</Events>"
        try:
            root = ET.fromstring(wrapped)
        except ET.ParseError:
            return []

        for ev_elem in root.findall(".//e:Event", NS):
            try:
                event = self._parse_single_event(ev_elem)
                if event:
                    events.append(event)
            except Exception:
                continue

        return events

    def _parse_single_event(self, ev_elem) -> dict | None:
        """Parse a single Event XML element."""
        sys_elem = ev_elem.find("e:System", NS)
        if sys_elem is None:
            return None

        event_id_elem = sys_elem.find("e:EventID", NS)
        if event_id_elem is None:
            return None
        event_id = int(event_id_elem.text)

        if event_id not in INTERESTING_IDS:
            return None

        # Dedup by record ID
        record_elem = sys_elem.find("e:EventRecordID", NS)
        if record_elem is not None:
            record_id = int(record_elem.text)
            if record_id <= self._last_record_id:
                return None
            self._last_record_id = record_id

        # Timestamp
        time_elem = sys_elem.find("e:TimeCreated", NS)
        ts = datetime.now(timezone.utc)
        if time_elem is not None:
            time_str = time_elem.get("SystemTime", "")
            try:
                ts = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
            except ValueError:
                pass

        # Extract EventData fields
        data = {}
        event_data = ev_elem.find("e:EventData", NS)
        if event_data is not None:
            for d in event_data.findall("e:Data", NS):
                name = d.get("Name", "")
                val = d.text or ""
                if name:
                    data[name] = val

        # Build normalized event
        ip = data.get("IpAddress", "").strip("-")
        username = data.get("TargetUserName", data.get("SubjectUserName", ""))
        logon_type = data.get("LogonType", "")
        severity = SEVERITY_MAP.get(event_id, "INFO")
        event_type = EVENT_NAMES.get(event_id, f"event_{event_id}")

        msg = f"[EID:{event_id}] {event_type.replace('_', ' ').title()}"
        if username:
            msg += f" — User: {username}"
        if ip and ip != "-":
            msg += f" — IP: {ip}"
        if logon_type:
            msg += f" — Type: {logon_type}"

        return {
            "source_name": self.source_name,
            "timestamp": ts,
            "severity": severity,
            "event_type": event_type,
            "message": msg,
            "raw_log": ET.tostring(ev_elem, encoding="unicode")[:1000],
            "ip_address": ip if ip else None,
            "username": username or None,
            "host": config.HOSTNAME,
            "os_type": self.os_type,
            "extra_data": {
                "event_id": event_id,
                "logon_type": logon_type,
                **{k: v for k, v in data.items() if k not in ("IpAddress", "TargetUserName", "SubjectUserName")},
            },
        }
