"""
core/threat_intel.py
NIGHTWATCH Threat Intelligence Module

Phase 1: In-memory blocklist only.
Phase 5 will add:
  - AbuseIPDB API integration
  - Sliding-window rate limiting with TTL
  - Auto-block after N violations
"""

from typing import Dict, Any, List


# ── In-memory blocklist (lost on restart — Phase 4 moves this to DB) ─
_BLOCKLIST: Dict[str, str] = {}   # ip → reason


def check_ip(ip: str) -> Dict[str, Any]:
    """
    Check whether an IP is blocked.

    Phase 1: checks local in-memory blocklist.
    Phase 5: will also query AbuseIPDB for global reputation.

    Returns:
        {
            "ip": str,
            "is_blocked": bool,
            "reason": str | None,
            "abuse_score": int | None,   # populated in Phase 5 (0–100)
            "source": str
        }
    """
    is_blocked = ip in _BLOCKLIST
    return {
        "ip":          ip,
        "is_blocked":  is_blocked,
        "reason":      _BLOCKLIST.get(ip),
        "abuse_score": None,          # Phase 5: AbuseIPDB score goes here
        "source":      "local_blocklist",
    }


def block_ip(ip: str, reason: str = "manual") -> None:
    """Add an IP to the local blocklist."""
    _BLOCKLIST[ip] = reason
    print(f"[ThreatIntel] ⛔ Blocked  : {ip}  | Reason: {reason}")


def unblock_ip(ip: str) -> None:
    """Remove an IP from the local blocklist."""
    if ip in _BLOCKLIST:
        del _BLOCKLIST[ip]
        print(f"[ThreatIntel] ✅ Unblocked: {ip}")
    else:
        print(f"[ThreatIntel] ℹ  IP not in blocklist: {ip}")


def get_blocked_ips() -> List[Dict[str, str]]:
    """Return list of all currently blocked IPs with their reasons."""
    return [{"ip": ip, "reason": reason} for ip, reason in _BLOCKLIST.items()]


# ── Stubs for Phase 5 ─────────────────────────────────────────────────

def query_abuseipdb(ip: str, api_key: str) -> Dict[str, Any]:
    """
    [STUB — Phase 5]
    Query AbuseIPDB for the reputation of an IP.
    Returns the abuse confidence score (0–100).
    """
    raise NotImplementedError("AbuseIPDB integration will be built in Phase 5")


def check_rate_limit(ip: str) -> Dict[str, Any]:
    """
    [STUB — Phase 5]
    Sliding-window rate limiter.
    Returns whether this IP has exceeded the request threshold.
    """
    raise NotImplementedError("Rate limiting will be built in Phase 5")
