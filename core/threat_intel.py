"""
core/threat_intel.py
NIGHTWATCH Threat Intelligence Module — 

Features:
  1. Sliding-window rate limiter (in-memory, per IP)
  2. AbuseIPDB integration (global IP reputation)
  3. In-memory blocklist (fast path, backed by SQLite in 

Flow for every request:
  check_ip(ip)
    → rate limit check  (too many requests? block)
    → local blocklist   (already known bad? block)
    → AbuseIPDB check   (globally known bad? block)
"""

import os
import time
import requests
from collections import defaultdict, deque
from typing import Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()

# ── Config from .env ──────────────────────────────────────────────────
ABUSEIPDB_ENABLED   = os.getenv("ABUSEIPDB_ENABLED", "false").lower() == "true"
ABUSEIPDB_API_KEY   = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSE_BLOCK_THRESH  = int(os.getenv("ABUSEIPDB_BLOCK_THRESHOLD", "50"))

RATE_LIMIT_MAX      = int(os.getenv("RATE_LIMIT_REQUESTS", "30"))
RATE_LIMIT_WINDOW   = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_BLOCK_TTL      = int(os.getenv("RATE_LIMIT_BLOCK_TTL_MINUTES", "60"))

# ── In-memory structures ──────────────────────────────────────────────
# Fast path — SQLite is the persistent backing store (

# ip → deque of timestamps (sliding window)
_rate_windows: Dict[str, deque] = defaultdict(deque)

# ip → reason  (in-memory blocklist — fast O(1) lookup)
_blocklist: Dict[str, str] = {}

# ip → expiry timestamp (unix time, None = permanent)
_blocklist_expiry: Dict[str, Optional[float]] = {}

# AbuseIPDB cache — avoid re-checking the same IP every request
# ip → {"score": int, "cached_at": float}
_abuse_cache: Dict[str, Dict] = {}
ABUSE_CACHE_TTL = 3600   # re-check IPs every hour


# ─────────────────────────────────────────────────────────────────────
#  RATE LIMITING
# ─────────────────────────────────────────────────────────────────────

def check_rate_limit(ip: str) -> Dict[str, Any]:
    """
    Sliding-window rate limiter.

    Keeps a deque of request timestamps for each IP.
    On each call, drops timestamps older than the window,
    then checks if the count exceeds the limit.

    Returns:
        {"limited": bool, "request_count": int, "limit": int, "window_sec": int}
    """
    now    = time.time()
    window = _rate_windows[ip]

    # Drop timestamps outside the window
    while window and now - window[0] > RATE_LIMIT_WINDOW:
        window.popleft()

    # Record this request
    window.append(now)
    count = len(window)

    if count > RATE_LIMIT_MAX:
        return {
            "limited":       True,
            "request_count": count,
            "limit":         RATE_LIMIT_MAX,
            "window_sec":    RATE_LIMIT_WINDOW,
            "message":       f"Rate limit exceeded: {count} requests in {RATE_LIMIT_WINDOW}s",
        }

    return {
        "limited":       False,
        "request_count": count,
        "limit":         RATE_LIMIT_MAX,
        "window_sec":    RATE_LIMIT_WINDOW,
    }


# ─────────────────────────────────────────────────────────────────────
#  LOCAL BLOCKLIST
# ─────────────────────────────────────────────────────────────────────

def _is_expired(ip: str) -> bool:
    """Check if a block has passed its TTL."""
    expiry = _blocklist_expiry.get(ip)
    if expiry is None:
        return False   # permanent
    return time.time() > expiry


def block_ip(ip: str, reason: str = "manual",
             ttl_minutes: Optional[int] = None) -> None:
    """
    Block an IP in memory.

    Args:
        ip:          IP to block
        reason:      Human-readable reason
        ttl_minutes: Auto-expiry (None = permanent)
    """
    _blocklist[ip] = reason
    if ttl_minutes:
        _blocklist_expiry[ip] = time.time() + ttl_minutes * 60
    else:
        _blocklist_expiry[ip] = None

    expiry_str = f"{ttl_minutes}min TTL" if ttl_minutes else "permanent"
    print(f"[ThreatIntel] ⛔ Blocked  : {ip} | {reason} | {expiry_str}")


def unblock_ip(ip: str) -> None:
    """Remove an IP from the in-memory blocklist."""
    if ip in _blocklist:
        del _blocklist[ip]
        _blocklist_expiry.pop(ip, None)
        print(f"[ThreatIntel] ✅ Unblocked: {ip}")
    else:
        print(f"[ThreatIntel] ℹ  Not in blocklist: {ip}")


def get_blocked_ips(self=None):
    """Return all currently active (non-expired) blocked IPs."""
    active = []
    expired_keys = []

    for ip, reason in _blocklist.items():
        if _is_expired(ip):
            expired_keys.append(ip)
        else:
            active.append({
                "ip":        ip,
                "reason":    reason,
                "permanent": _blocklist_expiry.get(ip) is None,
                "expires_at": _blocklist_expiry.get(ip),
            })

    # Clean up expired entries
    for ip in expired_keys:
        del _blocklist[ip]
        _blocklist_expiry.pop(ip, None)
        print(f"[ThreatIntel] ⏰ Block expired and removed: {ip}")

    return active


# ─────────────────────────────────────────────────────────────────────
#  ABUSEIPDB
# ─────────────────────────────────────────────────────────────────────

def query_abuseipdb(ip: str) -> Dict[str, Any]:
    """
    Query AbuseIPDB for the reputation of an IP.

    Returns:
        {
            "abuse_score":   int,     # 0–100 confidence of abuse
            "total_reports": int,
            "country":       str,
            "isp":           str,
            "source":        "abuseipdb" | "cache" | "error"
        }
    """
    if not ABUSEIPDB_ENABLED or not ABUSEIPDB_API_KEY:
        return {"abuse_score": 0, "source": "disabled"}

    # Check cache first
    cached = _abuse_cache.get(ip)
    if cached and time.time() - cached["cached_at"] < ABUSE_CACHE_TTL:
        result = dict(cached)
        result["source"] = "cache"
        return result

    # Query the API
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key":    ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={
                "ipAddress":     ip,
                "maxAgeInDays":  90,
                "verbose":       "",
            },
            timeout=3,   # don't slow down requests if API is slow
        )

        if response.status_code == 200:
            data   = response.json().get("data", {})
            result = {
                "abuse_score":   data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country":       data.get("countryCode", ""),
                "isp":           data.get("isp", ""),
                "source":        "abuseipdb",
                "cached_at":     time.time(),
            }
            # Cache the result
            _abuse_cache[ip] = result
            return result

        elif response.status_code == 429:
            print("[ThreatIntel] AbuseIPDB rate limit hit — daily quota reached")
            return {"abuse_score": 0, "source": "rate_limited"}

        else:
            return {"abuse_score": 0, "source": "error",
                    "error": f"HTTP {response.status_code}"}

    except requests.exceptions.Timeout:
        return {"abuse_score": 0, "source": "timeout"}
    except Exception as e:
        return {"abuse_score": 0, "source": "error", "error": str(e)}


# ─────────────────────────────────────────────────────────────────────
#  MAIN CHECK — called by proxy.py for every request
# ─────────────────────────────────────────────────────────────────────

def check_ip(ip: str) -> Dict[str, Any]:
    """
    Full IP threat check. Runs three checks in order:

    1. Rate limit  — too many requests? block immediately
    2. Local block — already on our list? block
    3. AbuseIPDB   — globally known bad? block

    Returns:
        {
            "ip":          str,
            "is_blocked":  bool,
            "reason":      str | None,
            "rate_info":   dict,
            "abuse_info":  dict | None,
            "source":      str,
        }
    """
    # ── Check 1: Rate limiting ────────────────────────────────────
    rate = check_rate_limit(ip)
    if rate["limited"]:
        block_ip(ip, reason="rate_limit", ttl_minutes=RATE_BLOCK_TTL)
        # Also persist to DB
        try:
            from storage.db import db_block_ip
            db_block_ip(ip, reason="rate_limit",
                        ttl_minutes=RATE_BLOCK_TTL, auto=True)
        except Exception:
            pass
        return {
            "ip":         ip,
            "is_blocked": True,
            "reason":     f"rate_limit: {rate['request_count']} requests in {rate['window_sec']}s",
            "rate_info":  rate,
            "source":     "rate_limit",
        }

    # ── Check 2: Local blocklist ──────────────────────────────────
    if ip in _blocklist and not _is_expired(ip):
        return {
            "ip":         ip,
            "is_blocked": True,
            "reason":     _blocklist[ip],
            "rate_info":  rate,
            "source":     "local_blocklist",
        }

    # Clean up if expired
    if ip in _blocklist and _is_expired(ip):
        del _blocklist[ip]
        _blocklist_expiry.pop(ip, None)

    # ── Check 3: AbuseIPDB ────────────────────────────────────────
    abuse = query_abuseipdb(ip)
    abuse_score = abuse.get("abuse_score", 0)

    if abuse_score >= ABUSE_BLOCK_THRESH:
        reason = f"abuseipdb_score:{abuse_score}"
        block_ip(ip, reason=reason, ttl_minutes=RATE_BLOCK_TTL)
        try:
            from storage.db import db_block_ip
            db_block_ip(ip, reason=reason,
                        ttl_minutes=RATE_BLOCK_TTL, auto=True)
        except Exception:
            pass
        return {
            "ip":         ip,
            "is_blocked": True,
            "reason":     reason,
            "rate_info":  rate,
            "abuse_info": abuse,
            "source":     "abuseipdb",
        }

    return {
        "ip":         ip,
        "is_blocked": False,
        "rate_info":  rate,
        "abuse_info": abuse if ABUSEIPDB_ENABLED else None,
        "source":     "clean",
    }
