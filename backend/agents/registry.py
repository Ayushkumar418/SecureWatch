"""
registry.py — Agent auto-discovery and registration.

Detects the current OS and returns the correct set of agents to run.
Agents that can't find their log source are gracefully skipped.
"""
import logging
import config

log = logging.getLogger("agent.registry")


def get_agents():
    """
    Return a list of agent instances appropriate for the current OS.
    Gracefully skips agents whose log sources don't exist.
    """
    agents = []

    if config.DEMO_MODE:
        log.info("🎭 DEMO MODE — using simulated log agents")
        return _get_demo_agents()

    if config.IS_LINUX:
        agents = _get_linux_agents()
    elif config.IS_WINDOWS:
        agents = _get_windows_agents()
    else:
        log.warning("Unsupported OS: %s — no agents available", config.OS_TYPE)

    if not agents:
        log.warning("No agents could be started. Check log file permissions.")

    return agents


def _get_linux_agents():
    """Discover and instantiate Linux agents based on available log files."""
    agents = []

    # Auth log (SSH, sudo, etc.)
    if config.LINUX_LOG_PATHS["auth"].exists():
        from agents.linux.auth_agent import AuthAgent
        agents.append(AuthAgent())
        log.info("  📋 auth.log found — AuthAgent will monitor SSH/sudo")
    else:
        log.info("  ⬚ auth.log not found — skipping AuthAgent")

    # Syslog
    if config.LINUX_LOG_PATHS["syslog"].exists():
        from agents.linux.syslog_agent import SyslogAgent
        agents.append(SyslogAgent())
        log.info("  📋 syslog found — SyslogAgent will monitor system events")
    else:
        log.info("  ⬚ syslog not found — skipping SyslogAgent")

    # Kernel log
    if config.LINUX_LOG_PATHS["kern"].exists():
        from agents.linux.kern_agent import KernAgent
        agents.append(KernAgent())
        log.info("  📋 kern.log found — KernAgent will monitor kernel events")
    else:
        log.info("  ⬚ kern.log not found — skipping KernAgent")

    # Apache
    if config.LINUX_LOG_PATHS["apache"].exists():
        from agents.linux.apache_agent import ApacheAgent
        agents.append(ApacheAgent())
        log.info("  📋 Apache access.log found — ApacheAgent will monitor HTTP")
    elif config.LINUX_LOG_PATHS["nginx"].exists():
        from agents.linux.apache_agent import ApacheAgent
        agents.append(ApacheAgent(log_path=config.LINUX_LOG_PATHS["nginx"]))
        log.info("  📋 Nginx access.log found — ApacheAgent will monitor HTTP")
    else:
        log.info("  ⬚ No web server log found — skipping HTTP agent")

    # Journald (systemd)
    try:
        import subprocess
        result = subprocess.run(
            ["journalctl", "--version"],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0:
            from agents.linux.journald_agent import JournaldAgent
            agents.append(JournaldAgent())
            log.info("  📋 journalctl available — JournaldAgent will monitor systemd")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        log.info("  ⬚ journalctl not available — skipping JournaldAgent")

    return agents


def _get_windows_agents():
    """Discover and instantiate Windows agents."""
    agents = []

    from agents.windows.security_agent import WindowsSecurityAgent
    agents.append(WindowsSecurityAgent())
    log.info("  📋 Windows Security Event Log — monitoring login/auth events")

    from agents.windows.system_agent import WindowsSystemAgent
    agents.append(WindowsSystemAgent())
    log.info("  📋 Windows System Event Log — monitoring services/shutdown")

    from agents.windows.defender_agent import WindowsDefenderAgent
    agents.append(WindowsDefenderAgent())
    log.info("  📋 Windows Defender — monitoring malware/protection events")

    from agents.windows.powershell_agent import WindowsPowerShellAgent
    agents.append(WindowsPowerShellAgent())
    log.info("  📋 PowerShell — monitoring suspicious script execution")

    return agents


def _get_demo_agents():
    """Return the legacy simulated log agents for demo/testing."""
    log.info("  🎭 Starting in demo mode with simulated logs")
    # The old agents that work with simulate_logs.py
    # We import them lazily so they don't break if running on Windows
    from agents.linux.auth_agent import AuthAgent
    from agents.linux.syslog_agent import SyslogAgent
    from agents.linux.apache_agent import ApacheAgent

    sim_agents = [
        AuthAgent(log_path=config.SIM_DIR / "auth.log"),
        SyslogAgent(log_path=config.SIM_DIR / "syslog"),
        ApacheAgent(log_path=config.SIM_DIR / "access.log"),
    ]
    return sim_agents
