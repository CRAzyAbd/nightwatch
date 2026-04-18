"""
core/engine.py
NIGHTWATCH Detection Pipeline Orchestrator

Phase 1 flow:
    Request → Normalize → Regex Rules → Feature Extraction → Risk Score → Verdict

Phase 2 will add: → ML Ensemble → Updated Risk Score
Phase 5 will add: → Threat Intel IP check (pre-filter)
"""

import re
from urllib.parse import unquote_plus
from typing import Dict, Any, List

from .regex_rules import RULES, Rule
from . import feature_extractor


# ── Severity → numeric risk score ────────────────────────────────────
SEVERITY_SCORE: Dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH":     0.7,
    "MEDIUM":   0.4,
    "LOW":      0.2,
}

# ── Verdict thresholds ────────────────────────────────────────────────
BLOCK_THRESHOLD   = 0.7   # risk_score >= this → BLOCK
MONITOR_THRESHOLD = 0.3   # risk_score >= this → MONITOR (log but allow)
# Below MONITOR_THRESHOLD → ALLOW


def _normalize(text: str) -> str:
    """
    Multi-layer URL decode (handles double/triple encoded payloads).
    Attackers encode payloads as %3Cscript%3E or even %253Cscript%253E
    to bypass naive regex checks.
    We decode up to 3 passes until stable.
    """
    result = text
    for _ in range(3):
        decoded = unquote_plus(result)
        if decoded == result:
            break
        result = decoded
    return result


def _collect_targets(request: Dict[str, Any]) -> List[str]:
    """
    Build the list of strings we run every regex rule against.

    We check:
      - URL
      - Request body
      - Every header value (Log4Shell hides in User-Agent, X-Forwarded-For, etc.)
      - Combined URL + body (for rules that span both fields)
    """
    url     = request.get("url", "")
    body    = request.get("body", "") or ""
    headers = request.get("headers", {}) or {}

    targets = [
        _normalize(url),
        _normalize(body),
        _normalize(url + " " + body),   # combined
    ]

    for key, value in headers.items():
        targets.append(_normalize(str(value)))

    return targets


def analyze(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main WAF analysis function.

    Args:
        request (dict):
            {
                "method":  "GET",
                "url":     "/search?q=...",
                "headers": {"User-Agent": "...", ...},
                "body":    "...",
                "ip":      "1.2.3.4"
            }

    Returns:
        {
            "blocked":       bool,
            "verdict":       "BLOCK" | "MONITOR" | "ALLOW",
            "risk_score":    float,   # 0.0 – 1.0
            "matched_rules": list,    # rule dicts that fired
            "features":      dict,    # numeric feature vector
            "request_summary": dict
        }
    """

    # ── Step 1: Collect normalized strings to match against ───────
    targets = _collect_targets(request)

    # ── Step 2: Run every regex rule against every target ─────────
    matched_rules: List[Dict] = []
    seen_rule_ids = set()   # prevent counting the same rule twice

    for rule in RULES:
        if rule.id in seen_rule_ids:
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
                seen_rule_ids.add(rule.id)
                break  # found in one target — no need to check others

    # ── Step 3: Extract numeric features ─────────────────────────
    features = feature_extractor.extract(request)

    # ── Step 4: Compute risk score ────────────────────────────────
    if matched_rules:
        # Take the max severity score among all matched rules
        risk_score = max(SEVERITY_SCORE.get(r["severity"], 0.0) for r in matched_rules)
    else:
        # Anomaly scoring even without a rule match:
        # High entropy + high special char ratio → suspicious but not certain
        risk_score = 0.0
        entropy_flag = features.get("combined_entropy", 0.0) > 4.5
        ratio_flag   = features.get("special_char_ratio", 0.0) > 0.15
        scanner_flag = features.get("user_agent_is_scanner", 0.0) == 1.0

        if entropy_flag and ratio_flag:
            risk_score = 0.35   # MONITOR-worthy anomaly
        if scanner_flag:
            risk_score = max(risk_score, 0.4)   # Known scanner → elevate

    # ── Step 5: Determine verdict ─────────────────────────────────
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
        "blocked":    blocked,
        "verdict":    verdict,
        "risk_score": round(risk_score, 4),
        "matched_rules": matched_rules,
        "features":   features,
        "request_summary": {
            "method": request.get("method", "?"),
            "url":    request.get("url", "?")[:120],
            "ip":     request.get("ip", "unknown"),
        },
    }
