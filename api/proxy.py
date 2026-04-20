"""
api/proxy.py
NIGHTWATCH Reverse Proxy Engine

How it works:
  Browser/Client
      ↓  HTTP request
  NIGHTWATCH proxy (port 5000)
      ↓  analyze(request)
      ├─ BLOCK   → return 403 JSON, never forward
      ├─ MONITOR → log + forward (allow but record)
      └─ ALLOW   → forward to backend
      ↓  forward to target app
  Target App (port 5001)
      ↓  response
  NIGHTWATCH proxy
      ↓  add security headers
  Browser/Client

This is a transparent WAF — the client doesn't need to change anything.
"""

import os
import time
import json
import logging
import requests as req_lib
from flask import Blueprint, request, Response, jsonify
from dotenv import load_dotenv

from core.engine import analyze
from core.threat_intel import check_ip, block_ip
from api.routes import record_stats
from storage.db import log_request, db_block_ip, db_check_ip

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────
TARGET_URL   = os.getenv("TARGET_URL", "http://127.0.0.1:5001")
PROXY_TIMEOUT = 10   # seconds to wait for backend response

# ── Logger ────────────────────────────────────────────────────────────
logger = logging.getLogger("nightwatch.proxy")

# ── Blueprint ─────────────────────────────────────────────────────────
proxy_bp = Blueprint("proxy", __name__)

# ── Security headers added to every proxied response ─────────────────
SECURITY_HEADERS = {
    "X-Content-Type-Options":    "nosniff",
    "X-Frame-Options":           "DENY",
    "X-XSS-Protection":          "1; mode=block",
    "Referrer-Policy":           "strict-origin-when-cross-origin",
    "X-Nightwatch-Protected":    "true",
}

# ── Headers to strip when forwarding (hop-by-hop headers) ────────────
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "host",   # We set this ourselves when forwarding
}


def _get_client_ip() -> str:
    """
    Get the real client IP.
    Checks X-Forwarded-For first (set by load balancers/Nginx).
    Falls back to direct remote address.
    """
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _block_response(result: dict, ip: str) -> Response:
    """Return a 403 response with details about why the request was blocked."""
    rules = result.get("matched_rules", [])
    attack_types = list(set(r["attack_type"] for r in rules))

    body = {
        "blocked":     True,
        "message":     "Request blocked by NIGHTWATCH WAF",
        "risk_score":  result.get("risk_score"),
        "attack_types": attack_types,
        "rules_fired": [r["id"] for r in rules],
        "ip":          ip,
    }

    logger.warning(
        f"BLOCKED | IP={ip} | score={result.get('risk_score')} | "
        f"types={attack_types} | url={request.path}"
    )

    resp = Response(
        response=json.dumps(body, indent=2),
        status=403,
        mimetype="application/json",
    )
    for k, v in SECURITY_HEADERS.items():
        resp.headers[k] = v
    resp.headers["X-Nightwatch-Verdict"] = "BLOCK"
    return resp


def _forward_request(ip: str, verdict: str) -> Response:
    """
    Forward the request to the backend target app and return its response.
    Strips hop-by-hop headers, adds X-Forwarded-For.
    """
    # Build forwarded URL
    target_url = TARGET_URL.rstrip("/") + request.full_path.rstrip("?")

    # Build headers to forward
    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP
    }
    forward_headers["X-Forwarded-For"]   = ip
    forward_headers["X-Nightwatch-Verdict"] = verdict
    forward_headers["Host"] = TARGET_URL.split("//")[-1]

    try:
        backend_resp = req_lib.request(
            method=request.method,
            url=target_url,
            headers=forward_headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=PROXY_TIMEOUT,
        )

        # Build Flask response from backend response
        excluded = HOP_BY_HOP | {"content-encoding", "content-length"}
        response_headers = {
            k: v for k, v in backend_resp.headers.items()
            if k.lower() not in excluded
        }

        flask_resp = Response(
            response=backend_resp.content,
            status=backend_resp.status_code,
            headers=response_headers,
        )

    except req_lib.exceptions.ConnectionError:
        flask_resp = Response(
            response=json.dumps({
                "error": "Backend unavailable",
                "message": f"NIGHTWATCH could not reach {TARGET_URL}. Is the target app running?",
            }),
            status=502,
            mimetype="application/json",
        )
    except req_lib.exceptions.Timeout:
        flask_resp = Response(
            response=json.dumps({"error": "Backend timeout"}),
            status=504,
            mimetype="application/json",
        )

    # Add security headers to every response
    for k, v in SECURITY_HEADERS.items():
        flask_resp.headers[k] = v
    flask_resp.headers["X-Nightwatch-Verdict"] = verdict

    return flask_resp


# ── Main proxy route — catches EVERYTHING ────────────────────────────

@proxy_bp.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@proxy_bp.route("/<path:path>",             methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def proxy(path):
    """
    The main WAF proxy handler.
    Every request to NIGHTWATCH hits this function.
    """
    start_time = time.time()
    ip = _get_client_ip()

    # ── Step 1: IP blocklist check (Phase 5 adds AbuseIPDB here) ──
    ip_status = check_ip(ip)
    if ip_status["is_blocked"]:
        logger.warning(f"BLOCKED (IP blocklist) | IP={ip} | reason={ip_status['reason']}")
        resp = Response(
            response=json.dumps({"blocked": True, "message": "Your IP is blocked", "reason": ip_status["reason"]}),
            status=403,
            mimetype="application/json",
        )
        for k, v in SECURITY_HEADERS.items():
            resp.headers[k] = v
        resp.headers["X-Nightwatch-Verdict"] = "BLOCK"
        return resp

    # ── Step 2: Build request dict for the engine ──────────────────
    body = request.get_data(as_text=True) or ""

    waf_request = {
        "method":  request.method,
        "url":     request.full_path.rstrip("?") or "/",
        "headers": dict(request.headers),
        "body":    body,
        "ip":      ip,
    }

    # ── Step 3: Analyze ────────────────────────────────────────────
    result  = analyze(waf_request)
    verdict = result["verdict"]
    record_stats(result)
    log_request(result, waf_request)   # Phase 4: persist to SQLite

    elapsed = round((time.time() - start_time) * 1000, 2)

    if verdict == "MONITOR":
        logger.info(
            f"MONITOR | IP={ip} | score={result['risk_score']} | "
            f"url={request.path} | {elapsed}ms"
        )

    # ── Step 4: Block or forward ───────────────────────────────────
    if verdict == "BLOCK":
        # Auto-block IPs that trigger CRITICAL rules
        critical_rules = [r for r in result.get("matched_rules", []) if r["severity"] == "CRITICAL"]
        if critical_rules:
            block_ip(ip, reason=f"auto: {critical_rules[0]['attack_type']}")
            db_block_ip(ip,
                        reason=f"auto: {critical_rules[0]['attack_type']}",
                        ttl_minutes=60,   # auto-blocks expire after 1 hour
                        auto=True)

        return _block_response(result, ip)

    return _forward_request(ip, verdict)
