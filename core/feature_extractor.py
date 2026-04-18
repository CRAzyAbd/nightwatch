"""
core/feature_extractor.py

Converts a raw HTTP request dict into a flat dict of numerical features.
These features feed the ML ensemble in Phase 2.
In Phase 1 they are used for anomaly scoring (entropy + special char ratio).

Input format:
    {
        "method":  "POST",
        "url":     "/api/login",
        "headers": {"User-Agent": "...", "Content-Type": "..."},
        "body":    "username=admin&password=...",
        "ip":      "1.2.3.4"
    }
"""

import re
import math
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, Any


# Characters commonly abused in injection attacks
_SPECIAL_CHARS = set("'\"<>(){}[];|&`$\\!%#@^~*")

# Known security scanner User-Agents
_SCANNER_PATTERN = re.compile(
    r"(sqlmap|nikto|nmap|masscan|burpsuite|burp\s|metasploit|dirbuster|"
    r"hydra|zgrab|nuclei|wfuzz|gobuster|acunetix|nessus|openvas|w3af|zap)",
    re.IGNORECASE
)

# SQL keywords that rarely appear in normal traffic
_SQL_KEYWORDS = [
    "select", "insert", "update", "delete", "drop", "union", "where",
    "having", "exec", "execute", "cast", "convert", "declare", "char",
    "nchar", "varchar", "concat", "substring", "ascii", "hex",
]


def _shannon_entropy(s: str) -> float:
    """
    Shannon entropy measures 'randomness' of a string.
    High entropy → obfuscated/encoded payload.
    Normal English text ≈ 3.5–4.5 bits.
    Random-looking strings like base64 ≈ 5.5–6.0 bits.
    """
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _special_char_count(s: str) -> int:
    return sum(1 for ch in s if ch in _SPECIAL_CHARS)


def _sql_keyword_count(s: str) -> int:
    s_lower = s.lower()
    return sum(1 for kw in _SQL_KEYWORDS if kw in s_lower)


def _has_encoded_chars(s: str) -> bool:
    """Detect URL/hex/unicode encoding — often used to bypass regex WAFs."""
    return bool(re.search(r'%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}', s))


def extract(request: Dict[str, Any]) -> Dict[str, float]:
    """
    Extract numerical features from an HTTP request.

    Returns:
        Dict[str, float] — feature_name → numeric value (all floats for ML compatibility)
    """
    method  = request.get("method", "GET").upper()
    url     = request.get("url", "")
    headers = request.get("headers", {}) or {}
    body    = request.get("body", "") or ""

    # ── Decode to catch encoded payloads ─────────────────────────
    url_decoded  = unquote(url)
    body_decoded = unquote(body)
    combined     = url_decoded + " " + body_decoded

    # ── Parse URL ─────────────────────────────────────────────────
    parsed       = urlparse(url)
    query_string = parsed.query
    params       = parse_qs(query_string)
    param_values = " ".join(v for vals in params.values() for v in vals)

    # ── Header helpers ────────────────────────────────────────────
    # Normalize header names to title case for consistency
    headers_lower = {k.lower(): v for k, v in headers.items()}
    user_agent    = headers_lower.get("user-agent", "")
    content_type  = headers_lower.get("content-type", "")

    # ── Build feature dict ────────────────────────────────────────
    combined_len = max(len(combined), 1)  # avoid division by zero

    features: Dict[str, float] = {

        # Length features — long inputs are suspicious
        "url_length":           float(len(url)),
        "query_string_length":  float(len(query_string)),
        "body_length":          float(len(body)),
        "param_values_length":  float(len(param_values)),

        # Count features
        "num_params":           float(len(params)),
        "num_headers":          float(len(headers)),
        "special_char_count":   float(_special_char_count(combined)),
        "sql_keyword_count":    float(_sql_keyword_count(combined)),

        # Ratio features — normalized counts
        "special_char_ratio":   float(_special_char_count(combined)) / combined_len,

        # Entropy features — high entropy = obfuscation risk
        "url_entropy":          _shannon_entropy(url_decoded),
        "body_entropy":         _shannon_entropy(body_decoded),
        "combined_entropy":     _shannon_entropy(combined),

        # Boolean indicator features (stored as 0.0 or 1.0)
        "has_encoded_chars":    float(_has_encoded_chars(combined)),

        "method_is_unusual":    float(method in ("TRACE", "CONNECT", "OPTIONS", "PROPFIND", "TRACK")),

        "has_script_tag":       float(bool(re.search(r"<\s*script", combined, re.IGNORECASE))),

        "has_dotdot":           float(".." in combined),

        "has_null_byte":        float("\x00" in combined or "%00" in combined),

        "has_jndi":             float("jndi" in combined.lower()),

        "has_template_expr":    float(bool(re.search(r"\{\{|\{%", combined))),

        "has_file_scheme":      float(bool(re.search(
            r"file://|dict://|gopher://", combined, re.IGNORECASE
        ))),

        "has_private_ip":       float(bool(re.search(
            r"127\.0\.0\.1|localhost|192\.168\.|10\.\d|172\.(1[6-9]|2\d|3[01])\.",
            combined, re.IGNORECASE
        ))),

        "has_sqli_comment":     float(bool(re.search(r"(--|#|/\*)", combined))),

        "has_union_select":     float(bool(re.search(r"union\s+select", combined, re.IGNORECASE))),

        # User-Agent features
        "user_agent_length":    float(len(user_agent)),
        "user_agent_is_empty":  float(len(user_agent) == 0),
        "user_agent_is_scanner": float(bool(_SCANNER_PATTERN.search(user_agent))),

        # Content-Type features
        "content_type_is_xml":  float("xml" in content_type.lower()),
        "content_type_is_json": float("json" in content_type.lower()),

        # Body structure heuristics
        "body_looks_like_xml":  float(
            body_decoded.strip().startswith("<") and "xml" in body_decoded[:50].lower()
        ),
        "body_looks_like_json": float(
            body_decoded.strip().startswith(("{", "["))
        ),
    }

    return features
