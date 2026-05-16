"""
manager.py — Unified threat intelligence manager.

Aggregates results from VirusTotal, AbuseIPDB, and any future providers.
Uses a local cache to avoid repeated API calls for the same IP.
"""
import logging
from datetime import datetime, timezone

log = logging.getLogger("threat_intel")


class ThreatIntelManager:
    """Aggregate threat intelligence from multiple providers."""

    def __init__(self):
        self.providers = []
        self._init_providers()

    def _init_providers(self):
        """Initialize available threat intel providers based on API keys."""
        import config

        if config.VIRUSTOTAL_API_KEY:
            try:
                from threat_intel.virustotal import VirusTotalClient
                self.providers.append(VirusTotalClient(config.VIRUSTOTAL_API_KEY))
                log.info("  ✅ VirusTotal provider enabled")
            except Exception as e:
                log.warning("  ❌ VirusTotal init failed: %s", e)

        if config.ABUSEIPDB_API_KEY:
            try:
                from threat_intel.abuseipdb import AbuseIPDBClient
                self.providers.append(AbuseIPDBClient(config.ABUSEIPDB_API_KEY))
                log.info("  ✅ AbuseIPDB provider enabled")
            except Exception as e:
                log.warning("  ❌ AbuseIPDB init failed: %s", e)

        if not self.providers:
            log.info("  ⬚ No threat intel API keys — running without enrichment")

    def lookup(self, ip: str) -> dict:
        """
        Look up an IP address across all providers.
        Returns aggregated results.
        """
        from threat_intel.cache import get_cached, set_cached

        # Check cache first
        cached = get_cached(ip)
        if cached is not None:
            return cached

        result = {
            "ip": ip,
            "risk_score": 0,
            "is_malicious": False,
            "country": None,
            "providers": {},
            "last_checked": datetime.now(timezone.utc).isoformat(),
        }

        for provider in self.providers:
            try:
                data = provider.check_ip(ip)
                if data:
                    result["providers"][provider.name] = data
                    # Aggregate risk score (take highest)
                    if data.get("risk_score", 0) > result["risk_score"]:
                        result["risk_score"] = data["risk_score"]
                    if data.get("is_malicious"):
                        result["is_malicious"] = True
                    if data.get("country") and not result["country"]:
                        result["country"] = data["country"]
            except Exception as e:
                log.warning("Provider %s failed for %s: %s", provider.name, ip, e)

        # Cache the result
        set_cached(ip, result)
        return result

    @property
    def available(self) -> bool:
        return len(self.providers) > 0
