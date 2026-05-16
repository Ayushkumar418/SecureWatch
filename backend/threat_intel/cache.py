"""
cache.py — Simple in-memory cache for threat intelligence lookups.

Caches IP reputation results for 24 hours to avoid repeated API calls.
"""
import time
import threading
import logging

log = logging.getLogger("threat_intel.cache")

_cache: dict[str, tuple[dict, float]] = {}
_lock = threading.Lock()
CACHE_TTL = 86400  # 24 hours


def get_cached(ip: str) -> dict | None:
    """Get cached threat intel for an IP, or None if expired/missing."""
    with _lock:
        entry = _cache.get(ip)
        if entry is None:
            return None
        data, ts = entry
        if time.time() - ts > CACHE_TTL:
            del _cache[ip]
            return None
        return data


def set_cached(ip: str, data: dict):
    """Store threat intel result in cache."""
    with _lock:
        _cache[ip] = (data, time.time())


def clear_cache():
    """Clear the entire cache."""
    with _lock:
        _cache.clear()


def cache_stats() -> dict:
    """Return cache statistics."""
    with _lock:
        now = time.time()
        valid = sum(1 for _, (_, ts) in _cache.items() if now - ts <= CACHE_TTL)
        return {"total": len(_cache), "valid": valid, "ttl": CACHE_TTL}
