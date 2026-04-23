"""
tests/test_phase8.py
NIGHTWATCH Phase 8 — JWT Auth Test
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


def get_token():
    r = client.post("/auth/login", json={
        "username": os.getenv("ADMIN_USERNAME", "admin"),
        "password": os.getenv("ADMIN_PASSWORD", "nightwatch2024"),
    })
    return r.get_json()["token"]


def run_tests():
    results = []

    # ── Login ─────────────────────────────────────────────────────
    def t_login_success():
        r = client.post("/auth/login", json={"username": "admin", "password": "nightwatch2024"})
        assert r.status_code == 200
        data = r.get_json()
        assert "token" in data
        assert data["token_type"] == "Bearer"
        assert data["username"] == "admin"

    results.append(test("Login with correct credentials → token", t_login_success))

    def t_login_wrong_pass():
        r = client.post("/auth/login", json={"username": "admin", "password": "wrongpassword"})
        assert r.status_code == 401

    results.append(test("Login with wrong password → 401", t_login_wrong_pass))

    def t_login_wrong_user():
        r = client.post("/auth/login", json={"username": "hacker", "password": "anything"})
        assert r.status_code == 401

    results.append(test("Login with wrong username → 401", t_login_wrong_user))

    def t_login_missing_fields():
        r = client.post("/auth/login", json={})
        assert r.status_code == 400

    results.append(test("Login with empty body → 400", t_login_missing_fields))

    # ── Auth status ───────────────────────────────────────────────
    def t_auth_status_valid():
        token = get_token()
        r = client.get("/auth/status", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["authenticated"] == True
        assert data["username"] == "admin"

    results.append(test("Auth status with valid token → authenticated=True", t_auth_status_valid))

    def t_auth_status_no_token():
        r = client.get("/auth/status")
        data = r.get_json()
        assert data["authenticated"] == False

    results.append(test("Auth status with no token → authenticated=False", t_auth_status_no_token))

    # ── Protected routes ──────────────────────────────────────────
    def t_logs_without_token():
        r = client.get("/api/logs")
        assert r.status_code == 401

    results.append(test("GET /api/logs without token → 401", t_logs_without_token))

    def t_logs_with_token():
        token = get_token()
        r = client.get("/api/logs", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert "logs" in r.get_json()

    results.append(test("GET /api/logs with valid token → 200", t_logs_with_token))

    def t_blocklist_add_without_token():
        r = client.post("/api/blocklist/add", json={"ip": "9.9.9.9"})
        assert r.status_code == 401

    results.append(test("POST /api/blocklist/add without token → 401", t_blocklist_add_without_token))

    # ── Token refresh ─────────────────────────────────────────────
    def t_refresh():
        token = get_token()
        r = client.post("/auth/refresh", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        data = r.get_json()
        assert "token" in data
        assert data["token"] != token   # new token issued

    results.append(test("Token refresh returns new token", t_refresh))

    # ── Invalid token ─────────────────────────────────────────────
    def t_invalid_token():
        r = client.get("/api/logs", headers={"Authorization": "Bearer faketoken.fake.fake"})
        assert r.status_code == 401

    results.append(test("Invalid token → 401", t_invalid_token))

    passed = sum(results)
    total  = len(results)
    print(f"\n{BOLD}{'═'*55}")
    color  = GREEN if passed == total else RED
    print(f"  Result: {color}{passed}/{total} passed{RESET}")
    print(f"{'═'*55}\n")
    return passed == total


if __name__ == "__main__":
    print(f"\n{BOLD}{CYAN}{'═'*55}{RESET}")
    print(f"{BOLD}{CYAN}  🦉 NIGHTWATCH — Phase 8 JWT Auth Tests{RESET}")
    print(f"{BOLD}{CYAN}{'═'*55}{RESET}\n")
    success = run_tests()
    sys.exit(0 if success else 1)
