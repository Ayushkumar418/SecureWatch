"""
powershell_agent.py — Monitors PowerShell operational event log.

Channel: Microsoft-Windows-PowerShell/Operational

Detects:
  • Encoded commands (-enc / -encodedcommand)
  • Download cradles (IEX, Invoke-WebRequest, Net.WebClient)
  • AMSI bypass attempts
  • Script block logging events (Event ID 4104)
  • Pipeline execution events (Event ID 4103)
"""
import subprocess
import xml.etree.ElementTree as ET
import re
import logging
import time
from datetime import datetime, timezone

from agents.base import BaseAgent
import config

log = logging.getLogger("agent.win_powershell")

# Event IDs: 4104 = script block, 4103 = pipeline exec
INTERESTING_IDS = {4104, 4103}

SUSPICIOUS_PATTERNS = re.compile(
    r"(-enc\s|-encodedcommand\s|invoke-expression|"
    r"\biex\b|invoke-webrequest|downloadstring|downloadfile|"
    r"new-object\s+net\.webclient|start-bitstransfer|"
    r"set-executionpolicy\s+bypass|set-executionpolicy\s+unrestricted|"
    r"-w\s+hidden|windowstyle\s+hidden|"
    r"amsiutils|amsiinitfailed|"
    r"mimikatz|rubeus|sharphound|bloodhound|"
    r"invoke-mimikatz|get-credential|"
    r"out-minidump|procdump)",
    re.IGNORECASE,
)

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
CHANNEL = "Microsoft-Windows-PowerShell/Operational"


class WindowsPowerShellAgent(BaseAgent):
    name = "win_powershell_agent"
    source_name = "powershell"
    os_type = "windows"

    def __init__(self):
        super().__init__()
        self._last_record_id = 0

    def collect(self):
        self.logger.info("Monitoring PowerShell script execution")
        while self._running:
            try:
                events = self._query_events()
                for ev in events:
                    if not self._running:
                        break
                    self.emit_event(ev)
            except Exception as e:
                self.logger.error("Error querying PowerShell log: %s", e)
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

        # Extract script block text
        script_block = ""
        event_data = ev_elem.find("e:EventData", NS)
        if event_data is not None:
            for d in event_data.findall("e:Data", NS):
                name = d.get("Name", "")
                if name == "ScriptBlockText" and d.text:
                    script_block = d.text[:2000]

        # Only report suspicious scripts (to avoid noise)
        is_suspicious = SUSPICIOUS_PATTERNS.search(script_block or "")

        if not is_suspicious and eid == 4104:
            return None  # Skip benign script blocks

        severity = "HIGH" if is_suspicious else "INFO"
        event_type = "suspicious_powershell" if is_suspicious else "powershell_exec"

        msg = f"[PS EID:{eid}] "
        if is_suspicious:
            msg += f"⚠️ Suspicious script detected: {script_block[:150]}"
        else:
            msg += f"Script execution: {script_block[:100]}"

        return {
            "source_name": self.source_name,
            "timestamp": ts,
            "severity": severity,
            "event_type": event_type,
            "message": msg,
            "raw_log": script_block[:1000] if script_block else ET.tostring(ev_elem, encoding="unicode")[:1000],
            "host": config.HOSTNAME,
            "os_type": self.os_type,
            "extra_data": {
                "event_id": eid,
                "script_preview": script_block[:500],
                "is_suspicious": bool(is_suspicious),
            },
        }
