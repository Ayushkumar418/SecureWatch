"""
threat_routes.py — API endpoints for threat intelligence lookups.
"""
import logging
from flask import Blueprint, jsonify, request

log = logging.getLogger("api.threat")

threat_bp = Blueprint("threat", __name__)

_manager = None


def get_manager():
    global _manager
    if _manager is None:
        try:
            from threat_intel.manager import ThreatIntelManager
            _manager = ThreatIntelManager()
        except Exception as e:
            log.warning("Threat intel not available: %s", e)
    return _manager


@threat_bp.get("/api/threat-intel/<ip>")
def lookup_ip(ip):
    """Look up threat intelligence for a single IP."""
    mgr = get_manager()
    if not mgr or not mgr.available:
        return jsonify({
            "ip": ip,
            "error": "No threat intel providers configured. Set VIRUSTOTAL_API_KEY or ABUSEIPDB_API_KEY.",
            "risk_score": 0,
            "providers": {},
        })

    result = mgr.lookup(ip)
    return jsonify(result)


@threat_bp.post("/api/threat-intel/batch")
def batch_lookup():
    """Look up threat intelligence for multiple IPs."""
    data = request.get_json(force=True)
    ips = data.get("ips", [])[:20]  # limit to 20 at a time

    mgr = get_manager()
    if not mgr or not mgr.available:
        return jsonify({"error": "No threat intel providers configured", "results": {}})

    results = {}
    for ip in ips:
        try:
            results[ip] = mgr.lookup(ip)
        except Exception as e:
            results[ip] = {"error": str(e)}

    return jsonify({"results": results})


@threat_bp.get("/api/threat-intel/status")
def ti_status():
    """Return threat intel provider status."""
    mgr = get_manager()
    from threat_intel.cache import cache_stats

    return jsonify({
        "available": mgr.available if mgr else False,
        "providers": [p.name for p in (mgr.providers if mgr else [])],
        "cache": cache_stats(),
    })
