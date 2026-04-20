"""
tests/test_phase4.py
NIGHTWATCH Phase 4 — Storage Test
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app

GREEN = "\033[92m"
RED   = "\033[91m"
CYAN  = "\033[96m"
BOLD  = "\033[1m"
RESET = "\033[0m"

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

    # Send some traffic to populate the DB
    with app.app_context():

        def t_log_written():
            # Trigger an analysis via the API
            client.post("/api/analyze", json={
                "method": "GET",
                "url": "/search?q=1' UNION SELECT * FROM users--",
                "headers": {"User-Agent": "Mozilla/5.0"},
                "body": "", "ip": "1.2.3.4"
            })
            # Check logs endpoint
            r = client.get("/api/logs?limit=10")
            assert r.status_code == 200
            data = r.get_json()
            assert "logs" in data
            assert data["count"] >= 1
            log = data["logs"][0]
            assert "verdict" in log
            assert "risk_score" in log
            assert "timestamp" in log

        results.append(test("Request logged to SQLite after analysis", t_log_written))

        def t_filter_by_verdict():
            r = client.get("/api/logs?verdict=BLOCK&limit=50")
            assert r.status_code == 200
            data = r.get_json()
            for log in data["logs"]:
                assert log["verdict"] == "BLOCK"

        results.append(test("Logs filterable by verdict=BLOCK", t_filter_by_verdict))

        def t_daily_stats():
            r = client.get("/api/stats/daily?days=7")
            assert r.status_code == 200
            data = r.get_json()
            assert "daily_stats" in data
            assert isinstance(data["daily_stats"], list)
            if data["daily_stats"]:
                day = data["daily_stats"][0]
                assert "date" in day
                assert "total" in day
                assert "blocked" in day

        results.append(test("Daily stats endpoint returns data", t_daily_stats))

        def t_top_attackers():
            r = client.get("/api/logs/attackers")
            assert r.status_code == 200
            data = r.get_json()
            assert "top_attackers" in data

        results.append(test("Top attackers endpoint works", t_top_attackers))

        def t_persistent_blocklist():
            # Block via API
            r = client.post("/api/blocklist/add", json={"ip": "6.6.6.6", "reason": "test"})
            assert r.status_code == 200

            # Check it's in DB
            from storage.db import db_check_ip
            status = db_check_ip("6.6.6.6")
            assert status["is_blocked"] == True
            assert status["reason"] == "test"

            # Unblock
            client.post("/api/blocklist/remove", json={"ip": "6.6.6.6"})
            status = db_check_ip("6.6.6.6")
            assert status["is_blocked"] == False

        results.append(test("IP blocklist persists to SQLite", t_persistent_blocklist))

        def t_db_file_exists():
            matches = [f for f in ["nightwatch.db", "instance/nightwatch.db"] if os.path.exists(f)]
            assert matches, "nightwatch.db file not created"

        results.append(test("nightwatch.db file created on disk", t_db_file_exists))

    passed = sum(results)
    total  = len(results)
    print(f"\n{BOLD}{'═'*55}")
    color  = GREEN if passed == total else RED
    print(f"  Result: {color}{passed}/{total} passed{RESET}")
    print(f"{'═'*55}\n")
    return passed == total


if __name__ == "__main__":
    print(f"\n{BOLD}{CYAN}{'═'*55}{RESET}")
    print(f"{BOLD}{CYAN}  🦉 NIGHTWATCH — Phase 4 Storage Tests{RESET}")
    print(f"{BOLD}{CYAN}{'═'*55}{RESET}\n")
    success = run_tests()
    sys.exit(0 if success else 1)
