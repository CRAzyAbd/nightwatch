"""
tests/test_phase5.py
NIGHTWATCH — Threat Intel Test
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
from core.threat_intel import (
    check_rate_limit, block_ip, unblock_ip,
    get_blocked_ips, check_ip, query_abuseipdb
)

GREEN = "\033[92m"
RED   = "\033[91m"
CYAN  = "\033[96m"
BOLD  = "\033[1m"
RESET = "\033[0m"


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

    # ── Rate limiter ──────────────────────────────────────────────
    def t_rate_limit_passes_normal():
        """Normal traffic should not be rate limited."""
        ip = "rate-test-1.0.0.1"
        for _ in range(5):
            result = check_rate_limit(ip)
        assert result["limited"] == False
        assert result["request_count"] == 5

    results.append(test("Rate limiter: 5 requests → not limited", t_rate_limit_passes_normal))

    def t_rate_limit_triggers():
        """Exceeding the limit should trigger a block."""
        ip    = "rate-test-2.0.0.2"
        limit = int(os.getenv("RATE_LIMIT_REQUESTS", "30"))
        for _ in range(limit + 5):
            result = check_rate_limit(ip)
        assert result["limited"] == True, f"Expected limited=True, got {result}"
        assert result["request_count"] > limit

    results.append(test("Rate limiter: exceeding limit → limited=True", t_rate_limit_triggers))

    def t_rate_window_slides():
        """Old requests outside the window should not count."""
        ip = "rate-test-3.0.0.3"
        from collections import deque
        from core.threat_intel import _rate_windows
        # Manually plant old timestamps (outside window)
        old_time = time.time() - 120   # 2 minutes ago
        _rate_windows[ip] = deque([old_time] * 5)
        # One new request should not count the old ones
        result = check_rate_limit(ip)
        assert result["request_count"] == 1   # only the current request

    results.append(test("Rate limiter: old requests outside window ignored", t_rate_window_slides))

    # ── Blocklist ─────────────────────────────────────────────────
    def t_block_unblock():
        ip = "block-test-1.0.0.4"
        block_ip(ip, reason="test")
        result = check_ip(ip)
        assert result["is_blocked"] == True
        assert result["reason"] == "test"
        unblock_ip(ip)
        result = check_ip(ip)
        assert result["is_blocked"] == False

    results.append(test("Block and unblock IP works", t_block_unblock))

    def t_ttl_expiry():
        """IP block with TTL=0 should expire immediately."""
        ip = "ttl-test-1.0.0.5"
        from core.threat_intel import _blocklist_expiry, _blocklist
        _blocklist[ip] = "ttl_test"
        _blocklist_expiry[ip] = time.time() - 1   # already expired
        result = check_ip(ip)
        assert result["is_blocked"] == False, "Expired block should not block"
        assert ip not in _blocklist, "Expired block should be cleaned up"

    results.append(test("TTL-expired block is auto-removed", t_ttl_expiry))

    def t_permanent_block():
        """IP block with no TTL should persist."""
        ip = "perm-test-1.0.0.6"
        block_ip(ip, reason="permanent_test", ttl_minutes=None)
        result = check_ip(ip)
        assert result["is_blocked"] == True
        unblock_ip(ip)

    results.append(test("Permanent block (no TTL) persists", t_permanent_block))

    def t_get_blocked_list():
        ip1 = "list-test-1.0.0.7"
        ip2 = "list-test-2.0.0.8"
        block_ip(ip1, "reason1")
        block_ip(ip2, "reason2")
        blocked = get_blocked_ips()
        ips = [b["ip"] for b in blocked]
        assert ip1 in ips
        assert ip2 in ips
        unblock_ip(ip1)
        unblock_ip(ip2)

    results.append(test("get_blocked_ips returns all active blocks", t_get_blocked_list))

    # ── AbuseIPDB (only if enabled) ───────────────────────────────
    if os.getenv("ABUSEIPDB_ENABLED", "false").lower() == "true":
        def t_abuseipdb_clean_ip():
            """8.8.8.8 (Google DNS) should have a low abuse score."""
            result = query_abuseipdb("8.8.8.8")
            assert result["source"] in ("abuseipdb", "cache")
            assert result["abuse_score"] < 10, \
                f"Google DNS shouldn't be flagged, got score={result['abuse_score']}"

        results.append(test("AbuseIPDB: 8.8.8.8 returns low score", t_abuseipdb_clean_ip))

        def t_abuseipdb_cache():
            """Second call for same IP should return from cache."""
            query_abuseipdb("1.1.1.1")
            result = query_abuseipdb("1.1.1.1")
            assert result["source"] == "cache"

        results.append(test("AbuseIPDB: second lookup uses cache", t_abuseipdb_cache))
    else:
        print(f"  [----] AbuseIPDB tests skipped (ABUSEIPDB_ENABLED=false in .env)")

    # ── Full check_ip integration ─────────────────────────────────
    def t_check_ip_clean():
        result = check_ip("clean-test-99.0.0.1")
        assert result["is_blocked"] == False
        assert "rate_info" in result

    results.append(test("check_ip: clean IP returns is_blocked=False", t_check_ip_clean))

    passed = sum(results)
    total  = len(results)
    print(f"\n{BOLD}{'═'*55}")
    color  = GREEN if passed == total else RED
    print(f"  Result: {color}{passed}/{total} passed{RESET}")
    print(f"{'═'*55}\n")
    return passed == total


if __name__ == "__main__":
    print(f"\n{BOLD}{CYAN}{'═'*55}{RESET}")
    print(f"{BOLD}{CYAN}  🦉 NIGHTWATCH — Threat Intel Tests{RESET}")
    print(f"{CYAN}  AbuseIPDB: {os.getenv('ABUSEIPDB_ENABLED','false')}{RESET}")
    print(f"{BOLD}{CYAN}{'═'*55}{RESET}\n")
    success = run_tests()
    sys.exit(0 if success else 1)
