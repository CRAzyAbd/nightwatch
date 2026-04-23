# 🦉 NIGHTWATCH

A modular, production-grade Web Application Firewall with an ML-powered detection engine.
Built from scratch on Ubuntu — combines regex-based rule matching with an ensemble of
three machine learning models to detect and block web attacks in real time.

## What it does

Every HTTP request passing through NIGHTWATCH goes through four gates:

1. **IP reputation check** — rate limiting, local blocklist, AbuseIPDB cross-reference
2. **Regex rule engine** — 30 handcrafted rules covering 10 attack classes
3. **Feature extraction** — 30 numerical features extracted per request
4. **ML ensemble** — Random Forest + XGBoost + LightGBM weighted soft vote

If the combined risk score exceeds the threshold, the request is blocked and logged.
Clean traffic is forwarded transparently to the backend.

## Architecture

<pre>
nightwatch/
│
├── core/                        Detection Engine
│   ├── engine.py                Orchestrator — combines regex + ML into a risk score
│   ├── regex_rules.py           30 rules across 10 attack types
│   ├── feature_extractor.py     Extracts 30 numerical features from each request
│   └── threat_intel.py          Rate limiter, IP blocklist, AbuseIPDB integration
│
├── ml/                          Machine Learning
│   ├── dataset_builder.py       Generates labeled training data from payload library
│   ├── trainer.py               Trains and evaluates all three models
│   ├── models.py                Ensemble inference — weighted soft voting
│   ├── drift_detector.py        Monitors prediction confidence over time
│   └── saved_models/            Serialized .joblib model files
│
├── api/                         Flask API
│   ├── routes.py                REST endpoints — stats, logs, rules, blocklist
│   ├── proxy.py                 Reverse proxy — intercepts and inspects all traffic
│   └── auth.py                  JWT authentication and route protection
│
├── storage/                     Persistence
│   └── db.py                    SQLite — request logs, blocklist, daily stats
│
├── dashboard/                   Web Interface
│   └── index.html               Real-time dashboard — charts, logs, blocklist
│
├── nginx/                       Production Server
│   └── nginx.conf               Network rate limiting, headers, upstream proxy
│
├── tests/                       Test suites — one file per phase
│
├── app.py                       Flask application factory
├── target_app.py                Vulnerable test application
├── wsgi.py                      Gunicorn entry point
├── Dockerfile
├── Dockerfile.target
└── docker-compose.yml
</pre>

## Traffic Flow

<pre>
Incoming Request
    │
    ▼
Nginx :80              Network-level rate limit + security headers
    │
    ▼
Gunicorn :8000         4 worker processes
    │
    ▼
threat_intel.py        Rate limit check → blocklist check → AbuseIPDB
    │
    ▼
engine.py
    ├── regex_rules.py     Pattern match against 30 rules
    ├── feature_extractor  Build 30-dimensional feature vector
    └── ml/models.py       RF + XGBoost + LightGBM → weighted probability
    │
    ├── score ≥ 0.65  ──►  Block  — 403 response + log + auto-block IP
    │
    └── score < 0.65  ──►  Forward to backend :5001
</pre>

## Attack Classes

<pre>
Class              Rules   Coverage
───────────────────────────────────────────────────────────────────
SQL Injection          5   UNION, boolean blind, time-based, schema enum, comments
XSS                    5   script tags, event handlers, JS URIs, media tags, CSS
Path Traversal         2   ../ sequences, sensitive file targeting
Command Injection      3   Unix/Windows shell metacharacters, subshell substitution
Shellshock             1   CVE-2014-6271 bash function definition in headers
Log4Shell              2   CVE-2021-44228 JNDI lookup + obfuscated nested variants
SSRF                   3   Private IP ranges, cloud metadata endpoints, URI schemes
XXE                    3   DOCTYPE injection, SYSTEM/PUBLIC entities, blind XXE
SSTI                   4   Jinja2/Twig, Python dunder access, Java template engines
HTTP Smuggling         2   CL.TE and TE.CL conflicts, obfuscated Transfer-Encoding
</pre>

## ML Model Performance

Trained on 560 labeled samples — 280 attack payloads across all 10 classes,
280 synthetically generated benign requests.

<pre>
Model            F1      Precision   Recall    ROC-AUC   CV F1 (5-fold)
───────────────────────────────────────────────────────────────────────
Random Forest    1.000   1.000       1.000     1.000     1.000 ± 0.000
XGBoost          1.000   1.000       1.000     1.000     1.000 ± 0.000
LightGBM         1.000   1.000       1.000     1.000     1.000 ± 0.000
───────────────────────────────────────────────────────────────────────
Ensemble         RF × 0.30 + XGBoost × 0.35 + LightGBM × 0.35
Block threshold  Combined score ≥ 0.65
</pre>

The 30 input features cover request length, parameter counts, special character
ratios, Shannon entropy of URL and body, boolean indicators for known-bad patterns
(JNDI, template expressions, dotdot sequences), and user-agent classification.

> Perfect scores are expected on this clean synthetic dataset. The regex layer
> handles known patterns with precision. The ML layer targets obfuscated and
> novel payloads that rules miss. Retrain with real traffic logs to improve
> real-world generalisation.

## API Reference

<pre>
Method   Endpoint                  Auth   Description
────────────────────────────────────────────────────────────────────
POST     /auth/login               No     Get JWT token
GET      /auth/status              No     Validate token
POST     /auth/refresh             Yes    Refresh token
POST     /api/analyze              No     Analyze a request dict
GET      /api/health               No     Health check
GET      /api/stats                No     Runtime statistics
GET      /api/rules                No     List all WAF rules
GET      /api/logs                 Yes    Request logs (filterable)
GET      /api/logs/attackers       Yes    Top attacking IPs
GET      /api/stats/daily          No     Daily stats — last 7 days
POST     /api/blocklist/add        Yes    Block an IP
POST     /api/blocklist/remove     Yes    Unblock an IP
GET      /api/blocklist            No     List blocked IPs
GET      /api/drift                No     ML drift status
GET      /api/threat/check/<ip>    No     IP reputation check
GET      /api/dashboard/data       No     All dashboard data in one call
</pre>

## Quick Start

**Development**

```bash
git clone https://github.com/CRAzyAbd/nightwatch.git
cd nightwatch
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python ml/dataset_builder.py
python ml/trainer.py
cp .env.example .env   # edit with your settings
python target_app.py &
python app.py
```

Open http://localhost:5000/ui

**Production**

```bash
docker-compose up --build
```

Open http://localhost/ui — default login: `admin` / `nightwatch2024`
Change credentials in `.env` before deploying publicly.

## Configuration

All settings are controlled via `.env`:


TARGET_URL                    Backend app URL (default: http://127.0.0.1:5001)
API_SECRET_KEY                Flask secret key
JWT_SECRET_KEY                JWT signing key
ADMIN_USERNAME                Dashboard login username
ADMIN_PASSWORD                Dashboard login password
ABUSEIPDB_API_KEY             AbuseIPDB API key (free tier: 1000 checks/day)
ABUSEIPDB_ENABLED             true / false
ABUSEIPDB_BLOCK_THRESHOLD     Score 0–100 above which to block (default: 50)
RATE_LIMIT_REQUESTS           Max requests per window (default: 30)
RATE_LIMIT_WINDOW_SECONDS     Window size in seconds (default: 60)
RATE_LIMIT_BLOCK_TTL_MINUTES  How long to auto-block rate violators (default: 60)

## Tech Stack

- **Python 3.12** — core language
- **Flask 3** — API and proxy server
- **scikit-learn / XGBoost / LightGBM** — ML models
- **SQLAlchemy + SQLite** — persistent storage
- **Nginx** — production reverse proxy
- **Gunicorn** — WSGI server
- **Docker + Compose** — containerised deployment
- **PyJWT + bcrypt** — authentication
