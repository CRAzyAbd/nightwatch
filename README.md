# 🦉 NIGHTWATCH — Modular ML-Powered Web Application Firewall

A production-grade WAF built from scratch with a dual-layer detection engine:
regex rules for known patterns + ML ensemble for novel/obfuscated attacks.

## Architecture

<pre>
nightwatch/
│
├── core/                        Detection Engine
│   ├── engine.py                Main orchestrator — ties regex + ML together
│   ├── regex_rules.py           30 custom rules across 10 attack types
│   ├── feature_extractor.py     Extracts 30 numerical features per request
│   └── threat_intel.py          Rate limiter + IP blocklist + AbuseIPDB
│
├── ml/                          Machine Learning Layer
│   ├── dataset_builder.py       Builds labeled CSV from 280+ attack payloads
│   ├── trainer.py               Trains RF + XGBoost + LightGBM
│   ├── models.py                Weighted soft voting ensemble (inference)
│   ├── drift_detector.py        Monitors model confidence over time
│   └── saved_models/            Trained .joblib model files
│
├── api/                         Flask API
│   ├── routes.py                All /api/* endpoints
│   ├── proxy.py                 Reverse proxy — intercepts all HTTP traffic
│   └── auth.py                  JWT login, token refresh, route protection
│
├── storage/                     Persistence Layer
│   └── db.py                    SQLite: logs, blocklist, daily stats
│
├── dashboard/                   Web Dashboard
│   └── index.html               Real-time UI with charts, logs, blocklist
│
├── nginx/                       Production Web Server
│   └── nginx.conf               Rate limiting, security headers, proxy
│
├── tests/                       Test Suites (one per phase)
│   ├── test_phase1.py
│   ├── test_phase2.py
│   ├── test_phase3.py
│   ├── test_phase4.py
│   ├── test_phase5.py
│   └── test_phase8.py
│
├── app.py                       Flask app factory + dashboard route
├── target_app.py                Deliberately vulnerable test target
├── wsgi.py                      Gunicorn entry point
├── Dockerfile                   WAF container
├── Dockerfile.target            Target app container
├── docker-compose.yml           Orchestrates all 3 containers
└── requirements.txt             All Python dependencies
</pre>

## Traffic Flow

<pre>
Internet
    │
    ▼
Nginx :80          network rate limit, security headers, block scanners
    │
    ▼
Gunicorn :8000     production WSGI server (4 workers)
    │
    ▼
NIGHTWATCH Engine
    ├── IP check   rate limit + local blocklist + AbuseIPDB
    ├── Regex      30 rules, instant block on CRITICAL match
    ├── Features   30 numerical features extracted
    └── ML         RF + XGBoost + LightGBM weighted soft vote
    │
    ├── BLOCK  ──► 403 response (never reaches backend)
    │
    └── ALLOW  ──► Target App :5001 (your protected backend)
</pre>

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

## ML Model Performance

Trained on 560 labeled samples (280 attack, 280 benign) generated from the built-in payload library.

<pre>
Model            F1      Precision   Recall    ROC-AUC   CV F1 (5-fold)
──────────────────────────────────────────────────────────────────────
Random Forest    1.000   1.000       1.000     1.000     1.000 ± 0.000
XGBoost          1.000   1.000       1.000     1.000     1.000 ± 0.000
LightGBM         1.000   1.000       1.000     1.000     1.000 ± 0.000
──────────────────────────────────────────────────────────────────────
Ensemble         Weighted soft vote — RF 30% + XGBoost 35% + LightGBM 35%
Block threshold  Combined score ≥ 0.65
</pre>

**Features used (30 total):**

<pre>
Length features    url_length, query_string_length, body_length, param_values_length
Count features     num_params, num_headers, special_char_count, sql_keyword_count
Ratio features     special_char_ratio
Entropy features   url_entropy, body_entropy, combined_entropy
Boolean features   has_encoded_chars, has_script_tag, has_dotdot, has_null_byte,
                   has_jndi, has_template_expr, has_file_scheme, has_private_ip,
                   has_sqli_comment, has_union_select, method_is_unusual,
                   user_agent_is_empty, user_agent_is_scanner,
                   content_type_is_xml, content_type_is_json,
                   body_looks_like_xml, body_looks_like_json
</pre>

> **Note:** Perfect scores reflect a clean synthetic dataset where attack and benign
> samples are clearly separable by the extracted features. Real-world performance
> will vary — the regex layer handles known patterns precisely, while ML catches
> obfuscated and novel payloads the rules miss. Retrain periodically with real
> traffic logs for best results.
