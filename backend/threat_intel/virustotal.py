"""
virustotal.py — VirusTotal IP reputation lookup.

Free tier: 4 requests/minute.
"""
import logging
import requests

log = logging.getLogger("threat_intel.virustotal")


class VirusTotalClient:
    name = "virustotal"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    def check_ip(self, ip: str) -> dict | None:
        """Query VirusTotal for IP reputation."""
        try:
            resp = requests.get(
                f"{self.base_url}/ip_addresses/{ip}",
                headers={"x-apikey": self.api_key},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) if stats else 1
                score = int((malicious / max(total, 1)) * 100)

                return {
                    "risk_score": score,
                    "is_malicious": malicious > 3,
                    "country": data.get("country"),
                    "as_owner": data.get("as_owner"),
                    "detections": malicious,
                    "total_engines": total,
                    "reputation": data.get("reputation", 0),
                }
            elif resp.status_code == 429:
                log.warning("VirusTotal rate limit hit")
                return None
            else:
                log.debug("VirusTotal returned %d for %s", resp.status_code, ip)
                return None
        except requests.RequestException as e:
            log.warning("VirusTotal request failed: %s", e)
            return None
