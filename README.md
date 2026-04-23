# 🦉 NIGHTWATCH — Modular ML-Powered Web Application Firewall

A production-grade WAF built from scratch with a dual-layer detection engine:
regex rules for known patterns + ML ensemble for novel/obfuscated attacks.

## Architecture

nightwatch/
│
├── core/                        # Detection Engine
│   ├── engine.py                # Main orchestrator — ties regex + ML together
│   ├── regex_rules.py           # 30 custom rules across 10 attack types
│   ├── feature_extractor.py     # Extracts 30 numerical features per request
│   └── threat_intel.py          # Rate limiter + IP blocklist + AbuseIPDB
│
├── ml/                          # Machine Learning Layer
│   ├── dataset_builder.py       # Builds labeled CSV from 280+ attack payloads
│   ├── trainer.py               # Trains RF + XGBoost + LightGBM
│   ├── models.py                # Weighted soft voting ensemble (inference)
│   ├── drift_detector.py        # Monitors model confidence over time
│   └── saved_models/            # Trained .joblib model files
│
├── api/                         # Flask API
│   ├── routes.py                # All /api/* endpoints
│   ├── proxy.py                 # Reverse proxy — intercepts all HTTP traffic
│   └── auth.py                  # JWT login, token refresh, route protection
│
├── storage/                     # Persistence Layer
│   └── db.py                    # SQLite tables: logs, blocklist, daily stats
│
├── dashboard/                   # Web Dashboard
│   └── index.html               # Real-time UI with charts, logs, blocklist
│
├── nginx/                       # Production Web Server
│   └── nginx.conf               # Rate limiting, security headers, proxy config
│
├── tests/                       # Test Suites (one per phase)
│   ├── test_phase1.py
│   ├── test_phase2.py
│   ├── test_phase3.py
│   ├── test_phase4.py
│   ├── test_phase5.py
│   └── test_phase8.py
│
├── app.py                       # Flask app factory + dashboard route
├── target_app.py                # Deliberately vulnerable test target
├── wsgi.py                      # Gunicorn entry point
├── Dockerfile                   # WAF container
├── Dockerfile.target            # Target app container
├── docker-compose.yml           # Orchestrates all 3 containers
└── requirements.txt             # All Python dependencies

## Traffic Flow

Internet
↓
Nginx :80          ← network rate limit, security headers, block scanners
↓
Gunicorn :8000     ← production WSGI server (4 workers)
↓
NIGHTWATCH Engine
├── IP check   ← rate limit + local blocklist + AbuseIPDB
├── Regex      ← 30 rules, instant block on CRITICAL match
├── Features   ← 30 numerical features extracted
└── ML         ← RF + XGBoost + LightGBM weighted soft vote
↓
Block (403) or Forward
↓
Target App :5001   ← your real backend (protected)

## Attack Classes Detected

| Type | Rules | Notes |
|------|-------|-------|
| SQLi | 5 | UNION, boolean, time-based, schema enum |
| XSS | 5 | script tags, event handlers, JS URIs |
| Path Traversal | 2 | ../ sequences, sensitive files |
| CMDi | 3 | Unix/Windows shell metacharacters |
| Shellshock | 1 | CVE-2014-6271 |
| Log4Shell | 2 | CVE-2021-44228, obfuscated variants |
| SSRF | 3 | Private IPs, cloud metadata, URI schemes |
| XXE | 3 | DOCTYPE, SYSTEM/PUBLIC, blind XXE |
| SSTI | 4 | Jinja2, Python dunder, Java templates |
| HTTP Smuggling | 2 | CL.TE, TE.CL conflicts |

## Quick Start

### Development
```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python ml/dataset_builder.py && python ml/trainer.py
python target_app.py &
python app.py
```

### Production (Docker)
```bash
docker-compose up --build
```

Open http://localhost/ui — login with admin / nightwatch2024

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | /auth/login | No | Get JWT token |
| GET | /auth/status | No | Check token validity |
| POST | /api/analyze | No | Analyze a request |
| GET | /api/health | No | Health check |
| GET | /api/stats | No | Runtime statistics |
| GET | /api/rules | No | List all WAF rules |
| GET | /api/logs | Yes | Request logs |
| GET | /api/logs/attackers | Yes | Top attacking IPs |
| GET | /api/stats/daily | No | Daily stats (7 days) |
| POST | /api/blocklist/add | Yes | Block an IP |
| POST | /api/blocklist/remove | Yes | Unblock an IP |
| GET | /api/drift | No | ML drift status |
| GET | /api/threat/check/<ip> | No | Check IP reputation |

## ML Ensemble

Three models trained on 560+ labeled samples:
- **Random Forest** (30% weight) — stable, interpretable
- **XGBoost** (35% weight) — strong on tabular data
- **LightGBM** (35% weight) — fast, handles imbalanced classes

Weighted soft voting. Block threshold: combined score ≥ 0.65.

## Compared to ShadowGuard

| Feature | ShadowGuard | NIGHTWATCH |
|---------|-------------|------------|
| Architecture | Monolithic | Modular |
| ML | Single model | RF+XGB+LGBM ensemble |
| Attack types | 6 | 10 (adds SSRF, XXE, SSTI, Smuggling) |
| Storage | In-memory | SQLite persistent |
| Rate limiting | Mentioned | Sliding-window + TTL |
| Auth | admin/admin | JWT |
| Threat intel | None | AbuseIPDB |
| Drift detection | None | Z-score monitoring |
| Dashboard | Basic | Real-time with charts |
| Deploy | Manual | Docker + Nginx |
