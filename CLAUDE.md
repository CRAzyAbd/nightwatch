# CLAUDE.md — NIGHTWATCH

> Context + roadmap for Claude Code. Read this fully before starting any task.

## Project
NIGHTWATCH is a modular, ML-based Web Application Firewall (Python, Flask, Docker).
A 4-gate pipeline inspects every HTTP request: IP reputation → regex rules (30) →
feature extraction (30 features) → ML ensemble (RF + XGBoost + LightGBM soft vote).
Score ≥ 0.65 → block. Has a reverse proxy, JWT auth, SQLite storage, and a live dashboard.

Repo layout:
- `core/` — engine.py (orchestrator), regex_rules.py, feature_extractor.py, threat_intel.py
- `ml/` — dataset_builder.py, trainer.py, models.py (inference), drift_detector.py, saved_models/
- `api/` — routes.py, proxy.py, auth.py
- `storage/db.py`, `dashboard/index.html`, `nginx/`, `tests/`, `app.py`, `target_app.py`

## How I want you to work (IMPORTANT)
- **One step at a time.** Give me ONE actionable step, then STOP and wait for me to say "done".
- **Commands before theory.** Show me the exact command or code to run first. Explain only after, and only briefly.
- **Be direct. Don't over-explain.** No walls of text.
- When re-explaining a concept, use a real-world analogy instead of repeating the same framing.
- **Every milestone ends with a git commit + push.** Wrap each completed milestone: `git add` → `git commit` with a clear message → `git push`.
- Don't ask "should I continue?" — just proceed to the next step when I say done.

## Known issues to fix
1. **ML is effectively disabled.** `core/engine.py` (~line 176) sets `risk_score = 0.0` when no
   regex rule matches, killing the ML contribution. The WAF currently behaves as regex-only.
2. **Models are overfit.** Trained on ~560 synthetic samples → perfect 1.000 F1 (a red flag, not a feature).
3. No CI/CD (`.github/workflows` missing). Tests are sparse. No benchmarks, no metrics/observability.

---

## ROADMAP

Work milestones in order. Each is a self-contained unit ending in commit + push.

### M5 — Make the ML real
Goal: train on real data, get honest metrics, re-enable real ML scoring.
- Download a real labeled web-attack dataset (CSIC 2010 HTTP is the standard; ~36k labeled
  normal/anomalous requests). Parse it into the same feature format `feature_extractor.extract()` produces.
- Extend `ml/dataset_builder.py` to ingest it alongside the existing synthetic payloads.
- Retrain via `ml/trainer.py`. Expect realistic scores (~0.93–0.98), NOT 1.000.
- Fix `core/engine.py`: when regex doesn't fire, let a high-confidence ML score (e.g. ≥ 0.85)
  actually drive the verdict instead of hard-zeroing it. Tune the threshold against the FP rate.
- Verify: clean traffic stays ALLOW, obfuscated attacks that bypass regex now get caught by ML.

### M6 — Benchmark harness + evidence
Goal: replace claims with numbers.
- Build `benchmark/run_benchmark.py`: send a corpus of known attack payloads + a corpus of
  benign requests through the engine, compute detection rate, false-positive rate, precision/recall.
- Measure latency: p50 / p95 / p99 added per request (the WAF must be fast to be usable).
- Output a results table; paste it into the README, replacing the synthetic 1.000 block.

### M7 — Adversarial evasion suite (the differentiator)
Goal: attack your own WAF, then harden it. This is the red-team story.
- Build `evasion/evade.py`: take payloads that NIGHTWATCH currently blocks, mutate them with
  known WAF-bypass techniques — double/triple URL encoding, case mixing, inline SQL comments
  (`/**/`), unicode/overlong encoding, whitespace tricks, nested obfuscation.
- Measure the bypass rate: how many mutated attacks slip through.
- Harden: add normalization/decoding passes and/or features that close the gaps. Re-measure.
- Document before/after bypass rates. This maps directly to AI red-teaming skills.

### M8 — Production polish
Goal: earn "production grade".
- GitHub Actions: `.github/workflows/ci.yml` — install deps, run pytest, run a linter (ruff/flake8) on push + PR.
- Flesh out the test suite (engine, ml, api, storage, threat_intel) to meaningful coverage.
- Observability: add a Prometheus `/metrics` endpoint (request count, block count, latency histogram,
  per-attack-class counters). Provide a Grafana dashboard JSON.
- Load test (locust or wrk) and record throughput in the README.

---

## Notes
- Activate the venv before running anything: `source venv/bin/activate`.
- Don't commit `.env`, `data/*.csv` dumps, or large datasets — check `.gitignore` first.
- Keep changes modular and consistent with the existing code style.
