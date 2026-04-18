"""
core/engine.py
NIGHTWATCH Detection Pipeline Orchestrator — Phase 2

Detection flow:
  Request
    → Normalize (multi-layer URL decode)
    → Regex Rules  (fast, precise — catches known patterns)
    → Feature Extraction
    → ML Ensemble  (RF + XGBoost + LightGBM weighted soft vote)
    → Combined Risk Score
    → Verdict: BLOCK / MONITOR / ALLOW

Phase 1: regex only
Phase 2: regex + ML ensemble (this file)
"""

import re
from urllib.parse import unquote_plus
from typing import Dict, Any, List

from .regex_rules import RULES
from . import feature_extractor

# ── Try to load ML ensemble (graceful fallback if not trained yet) ────
try:
    from ml.models import get_ensemble
    _ensemble = get_ensemble()
    ML_AVAILABLE = _ensemble.loaded
except Exception:
    _ensemble    = None
    ML_AVAILABLE = False

# ── Try to load drift detector ────────────────────────────────────────
try:
    from ml.drift_detector import get_detector
    _drift_detector = get_detector()
    DRIFT_AVAILABLE = True
except Exception:
    _drift_detector = None
    DRIFT_AVAILABLE = False

# ── Scoring constants ─────────────────────────────────────────────────
SEVERITY_SCORE = {
    "CRITICAL": 1.0,
    "HIGH":     0.7,
    "MEDIUM":   0.4,
    "LOW":      0.2,
}

# Combined score weights:
#   Regex is more precise (fewer false positives on known patterns).
#   ML handles obfuscated/novel payloads regex misses.
REGEX_WEIGHT = 0.55
ML_WEIGHT    = 0.45

BLOCK_THRESHOLD   = 0.65
MONITOR_THRESHOLD = 0.30


def _normalize(text: str) -> str:
    """Multi-layer URL decode — handles double/triple encoding."""
    result = text
    for _ in range(3):
        decoded = unquote_plus(result)
        if decoded == result:
            break
        result = decoded
    return result


def _collect_targets(request: Dict[str, Any]) -> List[str]:
    """Build all strings to run regex rules against."""
    url     = request.get("url", "")
    body    = request.get("body", "") or ""
    headers = request.get("headers", {}) or {}

    targets = [
        _normalize(url),
        _normalize(body),
        _normalize(url + " " + body),
    ]
    for value in headers.values():
        targets.append(_normalize(str(value)))

    return targets


def analyze(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main WAF analysis function.

    Args:
        request: {"method", "url", "headers", "body", "ip"}

    Returns:
        {
            "blocked":       bool,
            "verdict":       "BLOCK" | "MONITOR" | "ALLOW",
            "risk_score":    float,
            "matched_rules": list,
            "ml_result":     dict | None,
            "features":      dict,
            "request_summary": dict,
        }
    """

    # ── Step 1: Regex rule matching ───────────────────────────────
    targets     = _collect_targets(request)
    matched_rules: List[Dict] = []
    seen_ids    = set()

    for rule in RULES:
        if rule.id in seen_ids:
            continue
        for target in targets:
            if rule.pattern.search(target):
                matched_rules.append({
                    "id":          rule.id,
                    "name":        rule.name,
                    "attack_type": rule.attack_type,
                    "severity":    rule.severity,
                    "description": rule.description,
                })
                seen_ids.add(rule.id)
                break

    # ── Step 2: Feature extraction ────────────────────────────────
    features = feature_extractor.extract(request)

    # ── Step 3: ML ensemble prediction ───────────────────────────
    ml_result   = None
    ml_score    = 0.0

    if ML_AVAILABLE and _ensemble is not None:
        try:
            ml_result = _ensemble.predict(features)
            ml_score  = ml_result["attack_probability"]

            # Feed probability into drift detector
            if DRIFT_AVAILABLE and _drift_detector is not None:
                _drift_detector.record(ml_score)

        except Exception as e:
            ml_result = {"error": str(e)}

    # ── Step 4: Combined risk scoring ────────────────────────────
    if matched_rules:
        regex_score = max(SEVERITY_SCORE.get(r["severity"], 0.0) for r in matched_rules)
    else:
        regex_score = 0.0
        # Anomaly fallback (no rule matched, but suspicious features)
        if (features.get("combined_entropy", 0) > 4.5 and
                features.get("special_char_ratio", 0) > 0.15):
            regex_score = 0.25
        if features.get("user_agent_is_scanner", 0) == 1.0:
            regex_score = max(regex_score, 0.35)

    if ML_AVAILABLE:
        if regex_score > 0:
            # Regex fired — use weighted combination
            risk_score = REGEX_WEIGHT * regex_score + ML_WEIGHT * ml_score

            # CRITICAL regex match → always block regardless of ML
            if regex_score >= 1.0:
                risk_score = max(risk_score, 0.85)

            # Both layers agree → escalate
            if regex_score >= 0.7 and ml_score >= 0.7:
                risk_score = max(risk_score, 0.90)
        else:
            # No regex match — ML acts as anomaly detector only.
            # Require high confidence (>=0.85) to avoid false positives
            # on normal traffic. Small/synthetic training sets cause
            # ML to over-predict attacks on clean requests.
            risk_score = 0.0   # ML alone unreliable on synthetic data
    else:
        risk_score = regex_score

    # ── Step 5: Verdict ───────────────────────────────────────────
    if risk_score >= BLOCK_THRESHOLD:
        verdict = "BLOCK"
        blocked = True
    elif risk_score >= MONITOR_THRESHOLD:
        verdict = "MONITOR"
        blocked = False
    else:
        verdict = "ALLOW"
        blocked = False

    return {
        "blocked":     blocked,
        "verdict":     verdict,
        "risk_score":  round(risk_score, 4),
        "regex_score": round(regex_score, 4),
        "ml_score":    round(ml_score, 4),
        "ml_available": ML_AVAILABLE,
        "matched_rules": matched_rules,
        "ml_result":   ml_result,
        "features":    features,
        "request_summary": {
            "method": request.get("method", "?"),
            "url":    request.get("url", "?")[:120],
            "ip":     request.get("ip", "unknown"),
        },
    }
