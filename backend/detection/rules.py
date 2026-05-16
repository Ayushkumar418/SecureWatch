"""
rules.py — All detection rules for the SIEM engine.

Each rule is either:
  - InstantRule:  fires immediately on a single matching event
  - ThresholdRule: fires when N events match within a time window
                   (handled by the Correlator, not here)

Rules defined here cover both Linux and Windows event types.
"""
import re
import logging

log = logging.getLogger("detection.rules")


class BaseRule:
    """Base class for all detection rules."""
    rule_name: str = ""
    severity: str = "MEDIUM"
    description: str = ""

    def matches(self, event: dict) -> bool:
        """Return True if this event should trigger the rule."""
        return False

    def fire(self, event: dict) -> dict | None:
        """Create an alert dict when the rule triggers. Return None to skip."""
        return None


# ══════════════════════════════════════════════════════════════════════════
# INSTANT RULES — fire on a single event
# ══════════════════════════════════════════════════════════════════════════

class SQLiRule(BaseRule):
    """SQL injection pattern detected in HTTP request."""
    rule_name = "sqli_attempt"
    severity = "CRITICAL"

    SQLI_PATTERN = re.compile(
        r"(union\s+select|drop\s+table|insert\s+into|or\s+1=1|"
        r"'--|xp_cmdshell|benchmark\(|sleep\(|load_file|into\s+outfile)",
        re.IGNORECASE,
    )

    def matches(self, event: dict) -> bool:
        if event.get("source_name") not in ("apache", "nginx"):
            return False
        path = event.get("extra_data", {}).get("path", "")
        msg = event.get("message", "")
        return bool(self.SQLI_PATTERN.search(path) or self.SQLI_PATTERN.search(msg))

    def fire(self, event: dict) -> dict:
        ip = event.get("ip_address", "unknown")
        path = event.get("extra_data", {}).get("path", "")[:200]
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "title": f"SQL Injection Attempt from {ip}",
            "description": f"Suspicious SQL payload in request: {path}",
            "related_ips": [ip] if ip != "unknown" else [],
            "event_count": 1,
        }


class SensitivePathRule(BaseRule):
    """Request to sensitive file path (.env, .git, wp-login, etc.)."""
    rule_name = "sensitive_path"
    severity = "HIGH"

    SENSITIVE = re.compile(
        r"(\.env|\.git|/admin|/wp-login|/phpmyadmin|/etc/passwd|"
        r"/shell|/config|/backup|/\.htaccess|/xmlrpc\.php|"
        r"/\.aws|/\.ssh|/wp-config)",
        re.IGNORECASE,
    )

    def matches(self, event: dict) -> bool:
        if event.get("source_name") not in ("apache", "nginx"):
            return False
        path = event.get("extra_data", {}).get("path", "")
        return bool(self.SENSITIVE.search(path))

    def fire(self, event: dict) -> dict:
        ip = event.get("ip_address", "unknown")
        path = event.get("extra_data", {}).get("path", "")[:200]
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "title": f"Sensitive Path Access from {ip}",
            "description": f"Request to sensitive path: {path}",
            "related_ips": [ip] if ip != "unknown" else [],
            "event_count": 1,
        }


class RootLoginRule(BaseRule):
    """Direct root SSH login detected."""
    rule_name = "root_login"
    severity = "CRITICAL"

    def matches(self, event: dict) -> bool:
        return (
            event.get("event_type") in ("accepted_password", "root_login")
            and event.get("username") == "root"
        )

    def fire(self, event: dict) -> dict:
        ip = event.get("ip_address", "unknown")
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "title": f"Root SSH Login from {ip}",
            "description": "Direct root login via SSH — extremely dangerous.",
            "related_ips": [ip] if ip != "unknown" else [],
            "related_users": ["root"],
            "event_count": 1,
        }


class NewUserRule(BaseRule):
    """New system user account created."""
    rule_name = "user_created"
    severity = "HIGH"

    def matches(self, event: dict) -> bool:
        return event.get("event_type") in ("user_created", "new_user")

    def fire(self, event: dict) -> dict:
        user = event.get("username", "unknown")
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "title": f"New User Account Created: {user}",
            "description": f"User '{user}' was created — possible persistence technique.",
            "related_users": [user] if user != "unknown" else [],
            "event_count": 1,
        }


class OOMKillRule(BaseRule):
    """Linux OOM kill event."""
    rule_name = "oom_kill"
    severity = "MEDIUM"

    def matches(self, event: dict) -> bool:
        return event.get("event_type") == "oom_kill"

    def fire(self, event: dict) -> dict:
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "title": "OOM Kill — Process Killed by Kernel",
            "description": event.get("message", "Out of memory event detected."),
            "event_count": 1,
        }


# ── Windows Instant Rules ────────────────────────────────────────────────

class WindowsDefenderDisabledRule(BaseRule):
    """Windows Defender real-time protection disabled."""
    rule_name = "defender_disabled"
    severity = "CRITICAL"

    def matches(self, event: dict) -> bool:
        eid = event.get("extra_data", {}).get("event_id")
        return eid in (5001, 5010)

    def fire(self, event: dict) -> dict:
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "title": "Windows Defender Protection Disabled",
            "description": "Real-time protection or scanning was disabled — possible attacker action.",
            "event_count": 1,
        }


class WindowsMalwareDetectedRule(BaseRule):
    """Windows Defender detected malware."""
    rule_name = "malware_detected"
    severity = "CRITICAL"

    def matches(self, event: dict) -> bool:
        eid = event.get("extra_data", {}).get("event_id")
        return eid in (1116, 1117)

    def fire(self, event: dict) -> dict:
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "title": "Malware Detected by Windows Defender",
            "description": event.get("message", "Malware detection event."),
            "event_count": 1,
        }


class WindowsNewAdminRule(BaseRule):
    """User added to a security-enabled local group (e.g., Administrators)."""
    rule_name = "new_admin_account"
    severity = "CRITICAL"

    def matches(self, event: dict) -> bool:
        eid = event.get("extra_data", {}).get("event_id")
        return eid == 4732

    def fire(self, event: dict) -> dict:
        user = event.get("username", "unknown")
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "title": f"User Added to Admin Group: {user}",
            "description": f"User '{user}' was added to a security-enabled group.",
            "related_users": [user] if user != "unknown" else [],
            "event_count": 1,
        }


class WindowsServiceInstalledRule(BaseRule):
    """New service installed — potential persistence."""
    rule_name = "service_installed"
    severity = "HIGH"

    def matches(self, event: dict) -> bool:
        eid = event.get("extra_data", {}).get("event_id")
        return eid in (7045, 4697)

    def fire(self, event: dict) -> dict:
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "title": "New Service Installed",
            "description": event.get("message", "A new service was installed on the system."),
            "event_count": 1,
        }


class SuspiciousPowerShellRule(BaseRule):
    """Suspicious PowerShell activity (encoded commands, download cradles)."""
    rule_name = "suspicious_powershell"
    severity = "HIGH"

    SUSPICIOUS_PATTERNS = re.compile(
        r"(-enc\s|-encodedcommand\s|invoke-expression|iex\s|"
        r"invoke-webrequest|downloadstring|downloadfile|"
        r"new-object\s+net\.webclient|start-bitstransfer|"
        r"bypass|unrestricted|hidden\s+-w|amsiutils)",
        re.IGNORECASE,
    )

    def matches(self, event: dict) -> bool:
        if event.get("source_name") != "powershell":
            return False
        msg = event.get("message", "") + event.get("raw_log", "")
        return bool(self.SUSPICIOUS_PATTERNS.search(msg))

    def fire(self, event: dict) -> dict:
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "title": "Suspicious PowerShell Activity Detected",
            "description": event.get("message", "")[:300],
            "event_count": 1,
        }


# ══════════════════════════════════════════════════════════════════════════
# RULE REGISTRY
# ══════════════════════════════════════════════════════════════════════════

def get_all_rules() -> list[BaseRule]:
    """Return all active detection rules."""
    return [
        # Linux / Web
        SQLiRule(),
        SensitivePathRule(),
        RootLoginRule(),
        NewUserRule(),
        OOMKillRule(),
        # Windows
        WindowsDefenderDisabledRule(),
        WindowsMalwareDetectedRule(),
        WindowsNewAdminRule(),
        WindowsServiceInstalledRule(),
        SuspiciousPowerShellRule(),
    ]
