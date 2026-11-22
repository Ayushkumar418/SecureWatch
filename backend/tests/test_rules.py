"""Tests for detection/rules.py — instant rules."""
from detection.rules import (
    get_all_rules,
    SQLiRule,
    SensitivePathRule,
    RootLoginRule,
    NewUserRule,
    OOMKillRule,
    WindowsDefenderDisabledRule,
    WindowsMalwareDetectedRule,
    WindowsNewAdminRule,
    WindowsServiceInstalledRule,
    SuspiciousPowerShellRule,
)


def _apache(path, ip="1.2.3.4"):
    return {"source_name": "apache", "ip_address": ip,
            "extra_data": {"path": path}, "message": f"GET {path}"}


def test_registry_has_ten_rules():
    rules = get_all_rules()
    assert len(rules) == 10
    names = {r.rule_name for r in rules}
    assert names == {
        "sqli_attempt", "sensitive_path", "root_login", "user_created",
        "oom_kill", "defender_disabled", "malware_detected",
        "new_admin_account", "service_installed", "suspicious_powershell",
    }


def test_sqli_matches_union_select():
    rule = SQLiRule()
    ev = _apache("/search?q=1' UNION SELECT password FROM users")
    assert rule.matches(ev)
    alert = rule.fire(ev)
    assert alert["severity"] == "CRITICAL"
    assert alert["related_ips"] == ["1.2.3.4"]


def test_sqli_ignores_clean_path_and_other_sources():
    rule = SQLiRule()
    assert not rule.matches(_apache("/index.html"))
    assert not rule.matches(_apache("/about"))
    ev = {"source_name": "auth", "ip_address": "1.2.3.4",
          "extra_data": {"path": "/x?union select"}, "message": "union select"}
    assert not rule.matches(ev)


def test_sensitive_path_matches_dotenv_and_admin():
    rule = SensitivePathRule()
    assert rule.matches(_apache("/.env"))
    assert rule.matches(_apache("/wp-login.php"))
    assert rule.matches(_apache("/admin/dashboard"))
    assert not rule.matches(_apache("/products/123"))


def test_root_login_only_for_root():
    rule = RootLoginRule()
    assert rule.matches({"event_type": "accepted_password", "username": "root",
                         "ip_address": "5.6.7.8"})
    assert not rule.matches({"event_type": "accepted_password", "username": "ubuntu",
                             "ip_address": "5.6.7.8"})
    assert not rule.matches({"event_type": "failed_password", "username": "root",
                             "ip_address": "5.6.7.8"})


def test_new_user_rule():
    rule = NewUserRule()
    ev = {"event_type": "user_created", "username": "backdoor"}
    assert rule.matches(ev)
    assert rule.fire(ev)["title"].startswith("New User Account Created: backdoor")
    assert not rule.matches({"event_type": "accepted_password", "username": "x"})


def test_oom_kill_rule():
    rule = OOMKillRule()
    assert rule.matches({"event_type": "oom_kill"})
    assert not rule.matches({"event_type": "sudo_execution"})


def _win_event(event_id, source="security"):
    return {"source_name": source, "extra_data": {"event_id": event_id},
            "message": "test", "username": "alice"}


def test_windows_rules_fire_on_event_id():
    assert WindowsDefenderDisabledRule().matches(_win_event(5001))
    assert WindowsDefenderDisabledRule().matches(_win_event(5010))
    assert not WindowsDefenderDisabledRule().matches(_win_event(4624))
    assert WindowsMalwareDetectedRule().matches(_win_event(1116))
    assert WindowsNewAdminRule().matches(_win_event(4732))
    assert WindowsServiceInstalledRule().matches(_win_event(7045))
    assert WindowsServiceInstalledRule().matches(_win_event(4697))
    assert not WindowsServiceInstalledRule().matches(_win_event(4625))


def test_suspicious_powershell_matches_encoded_command():
    rule = SuspiciousPowerShellRule()
    ev = {"source_name": "powershell",
          "message": "powershell -enc SQBmACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
          "raw_log": ""}
    assert rule.matches(ev)
    assert not rule.matches({"source_name": "powershell",
                             "message": "Get-Process | Select-Object Name",
                             "raw_log": ""})
    assert not rule.matches({"source_name": "security",
                             "message": "powershell -enc abc", "raw_log": ""})
