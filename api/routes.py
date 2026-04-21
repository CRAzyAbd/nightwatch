import os
"""
api/routes.py
NIGHTWATCH Analysis API Routes

Endpoints:
  POST /api/analyze        — analyze a request dict, return verdict
  GET  /api/health         — health check
  GET  /api/stats          — runtime statistics
  GET  /api/rules          — list all loaded regex rules
  GET  /api/drift          — model drift status
  POST /api/blocklist/add  — manually block an IP
  POST /api/blocklist/remove — unblock an IP
  GET  /api/blocklist      — list blocked IPs
"""
from storage.db import (
    get_recent_logs, get_stats_last_n_days,
    get_top_attacking_ips, db_block_ip,
    db_unblock_ip, db_get_blocked_ips, db_check_ip
)
from flask import Blueprint, request, jsonify
from core.engine import analyze, ML_AVAILABLE
from core.regex_rules import RULES, list_attack_types
from core.threat_intel import block_ip, unblock_ip, get_blocked_ips, check_ip
import time

# ── Blueprint ─────────────────────────────────────────────────────────
api_bp = Blueprint("api", __name__, url_prefix="/api")

# ── Runtime stats (in-memory, Phase 4 moves these to SQLite) ─────────
_stats = {
    "start_time":     time.time(),
    "total_requests": 0,
    "blocked":        0,
    "monitored":      0,
    "allowed":        0,
    "attack_types":   {},
}


def record_stats(result: dict):
    """Update runtime counters after each analysis."""
    _stats["total_requests"] += 1
    verdict = result.get("verdict", "ALLOW")

    if verdict == "BLOCK":
        _stats["blocked"] += 1
    elif verdict == "MONITOR":
        _stats["monitored"] += 1
    else:
        _stats["allowed"] += 1

    for rule in result.get("matched_rules", []):
        atype = rule["attack_type"]
        _stats["attack_types"][atype] = _stats["attack_types"].get(atype, 0) + 1


# ─────────────────────────────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────────────────────────────

@api_bp.route("/health", methods=["GET"])
def health():
    """Health check — used by Docker and monitoring tools."""
    return jsonify({
        "status":       "ok",
        "ml_available": ML_AVAILABLE,
        "rules_loaded": len(RULES),
        "uptime_sec":   round(time.time() - _stats["start_time"], 1),
    })


@api_bp.route("/analyze", methods=["POST"])
def analyze_request():
    """
    Analyze an HTTP request dict and return a WAF verdict.

    Body (JSON):
        {
            "method":  "GET",
            "url":     "/search?q=...",
            "headers": {"User-Agent": "..."},
            "body":    "...",
            "ip":      "1.2.3.4"
        }

    Returns:
        {
            "blocked":       bool,
            "verdict":       "BLOCK" | "MONITOR" | "ALLOW",
            "risk_score":    float,
            "matched_rules": [...],
            "ml_result":     {...} | null
        }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    # Basic validation
    req = {
        "method":  data.get("method", "GET"),
        "url":     data.get("url", "/"),
        "headers": data.get("headers", {}),
        "body":    data.get("body", ""),
        "ip":      data.get("ip", request.remote_addr or "unknown"),
    }

    result = analyze(req)
    record_stats(result)

    from storage.db import log_request
    log_request(result, req)

    result.pop("features", None)
    return jsonify(result), 200


@api_bp.route("/stats", methods=["GET"])
def stats():
    """Return runtime statistics."""
    total = max(_stats["total_requests"], 1)
    return jsonify({
        "total_requests": _stats["total_requests"],
        "blocked":        _stats["blocked"],
        "monitored":      _stats["monitored"],
        "allowed":        _stats["allowed"],
        "block_rate":     round(_stats["blocked"] / total * 100, 2),
        "uptime_sec":     round(time.time() - _stats["start_time"], 1),
        "attack_types":   _stats["attack_types"],
        "ml_available":   ML_AVAILABLE,
    })


@api_bp.route("/rules", methods=["GET"])
def list_rules():
    """List all loaded regex rules."""
    return jsonify({
        "total": len(RULES),
        "attack_types": list_attack_types(),
        "rules": [
            {
                "id":          r.id,
                "name":        r.name,
                "attack_type": r.attack_type,
                "severity":    r.severity,
                "description": r.description,
            }
            for r in RULES
        ],
    })


@api_bp.route("/drift", methods=["GET"])
def drift_status():
    """Return ML model drift detection status."""
    try:
        from ml.drift_detector import get_detector
        detector = get_detector()
        return jsonify(detector.check())
    except Exception as e:
        return jsonify({"error": str(e), "status": "unavailable"}), 503


@api_bp.route("/blocklist", methods=["GET"])
def list_blocklist():
    """List all currently blocked IPs."""
    return jsonify({
        "blocked_ips": get_blocked_ips(),
        "total": len(get_blocked_ips()),
    })


@api_bp.route("/blocklist/add", methods=["POST"])
def add_to_blocklist():
    """Manually block an IP."""
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip")
    reason = data.get("reason", "manual")

    if not ip:
        return jsonify({"error": "ip field required"}), 400

    block_ip(ip, reason)
    db_block_ip(ip, reason=reason, auto=False)
    return jsonify({"message": f"IP {ip} blocked", "reason": reason})


@api_bp.route("/blocklist/remove", methods=["POST"])
def remove_from_blocklist():
    """Unblock an IP."""
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip")

    if not ip:
        return jsonify({"error": "ip field required"}), 400

    unblock_ip(ip)
    db_unblock_ip(ip)
    return jsonify({"message": f"IP {ip} unblocked"})

@api_bp.route("/logs", methods=["GET"])
def get_logs():
    """
    Return recent request logs from the database.
    Query params:
      ?limit=100       — max rows (default 100)
      ?verdict=BLOCK   — filter by verdict
    """
    limit   = min(int(request.args.get("limit", 100)), 1000)
    verdict = request.args.get("verdict")
    logs    = get_recent_logs(limit=limit, verdict=verdict)
    return jsonify({"logs": logs, "count": len(logs)})


@api_bp.route("/logs/attackers", methods=["GET"])
def top_attackers():
    """Return the IPs with the most blocked requests."""
    limit = int(request.args.get("limit", 10))
    return jsonify({"top_attackers": get_top_attacking_ips(limit=limit)})


@api_bp.route("/stats/daily", methods=["GET"])
def daily_stats():
    """Return daily stats for the last N days."""
    days = int(request.args.get("days", 7))
    return jsonify({"daily_stats": get_stats_last_n_days(n=days)})

@api_bp.route("/threat/check/<ip>", methods=["GET"])
def threat_check(ip):
    """
    On-demand threat check for a specific IP.
    Queries local blocklist + AbuseIPDB.
    Useful for investigating suspicious IPs from the logs.
    """
    from core.threat_intel import check_ip as ti_check
    result = ti_check(ip)
    return jsonify(result)


@api_bp.route("/threat/ratelimit", methods=["GET"])
def rate_limit_status():
    """Show current rate limit config."""
    return jsonify({
        "max_requests":   int(os.getenv("RATE_LIMIT_REQUESTS", "30")),
        "window_seconds": int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60")),
        "block_ttl_min":  int(os.getenv("RATE_LIMIT_BLOCK_TTL_MINUTES", "60")),
        "abuseipdb_enabled": os.getenv("ABUSEIPDB_ENABLED", "false").lower() == "true",
    })
