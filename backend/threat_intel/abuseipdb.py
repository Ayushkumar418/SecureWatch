"""
abuseipdb.py — AbuseIPDB reputation lookup.

Free tier: 1000 requests/day.
"""
import logging
import requests

log = logging.getLogger("threat_intel.abuseipdb")


class AbuseIPDBClient:
    name = "abuseipdb"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"

    def check_ip(self, ip: str) -> dict | None:
        """Query AbuseIPDB for IP reputation."""
        try:
            resp = requests.get(
                f"{self.base_url}/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={
                    "Key": self.api_key,
                    "Accept": "application/json",
                },
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                return {
                    "risk_score": score,
                    "is_malicious": score > 50,
                    "country": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "total_reports": data.get("totalReports", 0),
                    "usage_type": data.get("usageType"),
                    "is_tor": data.get("isTor", False),
                    "is_public": data.get("isPublic", True),
                }
            elif resp.status_code == 429:
                log.warning("AbuseIPDB rate limit hit")
                return None
            else:
                log.debug("AbuseIPDB returned %d for %s", resp.status_code, ip)
                return None
        except requests.RequestException as e:
            log.warning("AbuseIPDB request failed: %s", e)
            return None
