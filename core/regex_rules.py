"""
core/regex_rules.py
NIGHTWATCH Custom Ruleset v1.0

Attack classes covered:
  SQLi, XSS, PathTraversal, CMDi, Shellshock,
  Log4Shell, SSRF, XXE, SSTI, HTTPSmuggling

Each Rule has:
  id          — unique rule ID (NW-TYPE-NNN)
  name        — human-readable name
  pattern     — compiled regex (re.IGNORECASE applied everywhere)
  attack_type — category string
  severity    — CRITICAL / HIGH / MEDIUM / LOW
  description — what this rule catches and why
"""

import re
from dataclasses import dataclass
from typing import List


@dataclass
class Rule:
    id: str
    name: str
    pattern: re.Pattern
    attack_type: str
    severity: str
    description: str


# ──────────────────────────────────────────────────────────────────────
#  NIGHTWATCH RULESET
# ──────────────────────────────────────────────────────────────────────

RULES: List[Rule] = [

    # ═══════════════════════════════════════════════════════════════
    # SQL INJECTION
    # ═══════════════════════════════════════════════════════════════

    Rule(
        id="NW-SQL-001",
        name="SQLi UNION SELECT",
        pattern=re.compile(r"union\s+(?:all\s+)?select", re.IGNORECASE),
        attack_type="SQLi",
        severity="CRITICAL",
        description="Classic UNION-based SQLi — dumps data from other tables"
    ),
    Rule(
        id="NW-SQL-002",
        name="SQLi Boolean-based (OR/AND)",
        pattern=re.compile(r"(\bor\b|\band\b)\s+[\w'\"\d]+\s*=\s*[\w'\"\d]+", re.IGNORECASE),
        attack_type="SQLi",
        severity="HIGH",
        description="Boolean blind SQLi — OR 1=1, AND 1=1 patterns"
    ),
    Rule(
        id="NW-SQL-003",
        name="SQLi Comment Terminator",
        pattern=re.compile(r"(--|#|\/\*|\*\/)", re.IGNORECASE),
        attack_type="SQLi",
        severity="HIGH",
        description="SQL comment characters used to truncate the original query"
    ),
    Rule(
        id="NW-SQL-004",
        name="SQLi Time-based (SLEEP/BENCHMARK)",
        pattern=re.compile(
            r"(sleep\s*\(|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay)",
            re.IGNORECASE
        ),
        attack_type="SQLi",
        severity="CRITICAL",
        description="Time-based blind SQLi — causes server delay to infer data"
    ),
    Rule(
        id="NW-SQL-005",
        name="SQLi Schema Enumeration",
        pattern=re.compile(
            r"(information_schema|sys\.tables|sysobjects|pg_catalog|sqlite_master)",
            re.IGNORECASE
        ),
        attack_type="SQLi",
        severity="CRITICAL",
        description="Attacker querying the DB schema to map tables and columns"
    ),

    # ═══════════════════════════════════════════════════════════════
    # CROSS-SITE SCRIPTING (XSS)
    # ═══════════════════════════════════════════════════════════════

    Rule(
        id="NW-XSS-001",
        name="XSS Script Tag",
        pattern=re.compile(r"<\s*script[^>]*>", re.IGNORECASE),
        attack_type="XSS",
        severity="CRITICAL",
        description="Direct <script> tag injection — most obvious XSS vector"
    ),
    Rule(
        id="NW-XSS-002",
        name="XSS Event Handler Attribute",
        pattern=re.compile(
            r"on(load|error|click|mouseover|focus|blur|submit|change|keyup|keydown|input)\s*=",
            re.IGNORECASE
        ),
        attack_type="XSS",
        severity="HIGH",
        description="HTML event handler (onerror=, onclick=, etc.) injection"
    ),
    Rule(
        id="NW-XSS-003",
        name="XSS javascript: URI Scheme",
        pattern=re.compile(r"javascript\s*:", re.IGNORECASE),
        attack_type="XSS",
        severity="HIGH",
        description="javascript: URI in href/src — executes JS on click/load"
    ),
    Rule(
        id="NW-XSS-004",
        name="XSS Media/Embed Tag Payload",
        pattern=re.compile(
            r"<\s*(svg|img|iframe|body|input|embed|object|video|audio)[^>]*(src|action|data|href)\s*=",
            re.IGNORECASE
        ),
        attack_type="XSS",
        severity="HIGH",
        description="XSS hidden inside media/embed tags via attribute injection"
    ),
    Rule(
        id="NW-XSS-005",
        name="XSS CSS expression()/vbscript",
        pattern=re.compile(r"(expression\s*\(|vbscript\s*:|mocha\s*:)", re.IGNORECASE),
        attack_type="XSS",
        severity="HIGH",
        description="Legacy IE CSS expression() or VBScript URI schemes"
    ),

    # ═══════════════════════════════════════════════════════════════
    # PATH TRAVERSAL
    # ═══════════════════════════════════════════════════════════════

    Rule(
        id="NW-PATH-001",
        name="Path Traversal ../ Sequences",
        pattern=re.compile(
            r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f|\.\.%2f|\.\.%5c)",
            re.IGNORECASE
        ),
        attack_type="PathTraversal",
        severity="HIGH",
        description="Directory traversal via ../ — including URL-encoded variants"
    ),
    Rule(
        id="NW-PATH-002",
        name="Path Traversal Sensitive File Access",
        pattern=re.compile(
            r"(etc/passwd|etc/shadow|etc/hosts|win\.ini|system32|boot\.ini|web\.config|\.htaccess|\.env)",
            re.IGNORECASE
        ),
        attack_type="PathTraversal",
        severity="CRITICAL",
        description="Explicit targeting of known sensitive system or config files"
    ),

    # ═══════════════════════════════════════════════════════════════
    # COMMAND INJECTION
    # ═══════════════════════════════════════════════════════════════

    Rule(
        id="NW-CMD-001",
        name="CMDi Unix Shell Metacharacters",
        pattern=re.compile(
            r"([;&|`]\s*(ls|cat|id|whoami|uname|pwd|wget|curl|bash|sh|python|perl|nc|ncat|netcat|rm\s+-rf))",
            re.IGNORECASE
        ),
        attack_type="CMDi",
        severity="CRITICAL",
        description="Shell metacharacters (;, &, |, `) followed by Unix commands"
    ),
    Rule(
        id="NW-CMD-002",
        name="CMDi Windows Commands",
        pattern=re.compile(
            r"([;&|`]\s*(dir|type|net\s+user|ipconfig|systeminfo|cmd\.exe|powershell|wscript|cscript))",
            re.IGNORECASE
        ),
        attack_type="CMDi",
        severity="CRITICAL",
        description="Command injection targeting Windows system commands"
    ),
    Rule(
        id="NW-CMD-003",
        name="CMDi Backtick/Subshell Substitution",
        pattern=re.compile(r"(`[^`]+`|\$\([^)]+\))", re.IGNORECASE),
        attack_type="CMDi",
        severity="HIGH",
        description="Backtick or $() used for command substitution in shells"
    ),

    # ═══════════════════════════════════════════════════════════════
    # SHELLSHOCK (CVE-2014-6271)
    # ═══════════════════════════════════════════════════════════════

    Rule(
        id="NW-SHELL-001",
        name="Shellshock Bash Function Definition",
        pattern=re.compile(r"\(\s*\)\s*\{[^}]*\}\s*;", re.IGNORECASE),
        attack_type="Shellshock",
        severity="CRITICAL",
        description="Bash Shellshock — malicious function definition in HTTP headers"
    ),

    # ═══════════════════════════════════════════════════════════════
    # LOG4SHELL (CVE-2021-44228)
    # ═══════════════════════════════════════════════════════════════

    Rule(
        id="NW-L4S-001",
        name="Log4Shell JNDI Lookup",
        pattern=re.compile(
            r"\$\{(jndi|lower|upper|env|sys|java|main|k8s|docker|web)[^}]*\}",
            re.IGNORECASE
        ),
        attack_type="Log4Shell",
        severity="CRITICAL",
        description="Log4j JNDI expression — triggers remote class loading"
    ),
    Rule(
        id="NW-L4S-002",
        name="Log4Shell Obfuscated via Nested Expressions",
        pattern=re.compile(r"\$\{.*j.*n.*d.*i.*}", re.IGNORECASE),
        attack_type="Log4Shell",
        severity="CRITICAL",
        description="Log4Shell hidden via nested ${lower:j}${lower:n}${lower:d}${lower:i} tricks"
    ),

    # ═══════════════════════════════════════════════════════════════
    # SSRF — Server-Side Request Forgery
    # ═══════════════════════════════════════════════════════════════

    Rule(
        id="NW-SSRF-001",
        name="SSRF Private/Internal IP Target",
        pattern=re.compile(
            r"(https?|ftp)://(127\.0\.0\.1|localhost|0\.0\.0\.0|"
            r"169\.254\.|10\.\d+\.\d+\.\d+|"
            r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.)",
            re.IGNORECASE
        ),
        attack_type="SSRF",
        severity="CRITICAL",
        description="URL targeting RFC1918 private or loopback addresses — classic SSRF"
    ),
    Rule(
        id="NW-SSRF-002",
        name="SSRF Cloud Metadata Endpoint",
        pattern=re.compile(
            r"169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2",
            re.IGNORECASE
        ),
        attack_type="SSRF",
        severity="CRITICAL",
        description="AWS IMDSv1/v2, GCP, or Azure metadata service access attempt"
    ),
    Rule(
        id="NW-SSRF-003",
        name="SSRF Dangerous URI Schemes",
        pattern=re.compile(
            r"(file://|dict://|gopher://|sftp://|tftp://|ldap://|jar://)",
            re.IGNORECASE
        ),
        attack_type="SSRF",
        severity="HIGH",
        description="Non-HTTP URI schemes leveraged for SSRF lateral movement"
    ),

    # ═══════════════════════════════════════════════════════════════
    # XXE — XML External Entity Injection
    # ═══════════════════════════════════════════════════════════════

    Rule(
        id="NW-XXE-001",
        name="XXE DOCTYPE with Internal Subset",
        pattern=re.compile(r"<!DOCTYPE[^>]*\[", re.IGNORECASE),
        attack_type="XXE",
        severity="CRITICAL",
        description="XML DOCTYPE with inline entity definitions — XXE setup"
    ),
    Rule(
        id="NW-XXE-002",
        name="XXE SYSTEM/PUBLIC External Entity",
        pattern=re.compile(r"<!ENTITY\s+\w+\s+(SYSTEM|PUBLIC)\s+['\"]", re.IGNORECASE),
        attack_type="XXE",
        severity="CRITICAL",
        description="External entity declaration pointing to a file or URL"
    ),
    Rule(
        id="NW-XXE-003",
        name="XXE Parameter Entity (Blind XXE)",
        pattern=re.compile(r"<!ENTITY\s+%\s+\w+", re.IGNORECASE),
        attack_type="XXE",
        severity="CRITICAL",
        description="XML parameter entity used for out-of-band (blind) XXE"
    ),

    # ═══════════════════════════════════════════════════════════════
    # SSTI — Server-Side Template Injection
    # ═══════════════════════════════════════════════════════════════

    Rule(
        id="NW-SSTI-001",
        name="SSTI Jinja2/Twig Expression",
        pattern=re.compile(r"(\{\{[^}]*\}\}|\{%[^%]*%\})", re.IGNORECASE),
        attack_type="SSTI",
        severity="HIGH",
        description="Jinja2/Twig template expression in user-controlled input"
    ),
    Rule(
        id="NW-SSTI-002",
        name="SSTI Arithmetic Probe",
        pattern=re.compile(r"\{\{\s*\d+\s*[\*\+\-\/]\s*\d+\s*\}\}", re.IGNORECASE),
        attack_type="SSTI",
        severity="HIGH",
        description="Math expression inside template delimiters — standard SSTI detection probe"
    ),
    Rule(
        id="NW-SSTI-003",
        name="SSTI Python Dunder Attribute Access",
        pattern=re.compile(
            r"(__class__|__mro__|__subclasses__|__builtins__|__globals__|__import__)",
            re.IGNORECASE
        ),
        attack_type="SSTI",
        severity="CRITICAL",
        description="Python internal attribute access — sandbox escape leading to RCE"
    ),
    Rule(
        id="NW-SSTI-004",
        name="SSTI FreeMarker/Velocity (Java Templates)",
        pattern=re.compile(r"(\$\{.*\.exec\(|#set\s*\(|\$\{.*Runtime)", re.IGNORECASE),
        attack_type="SSTI",
        severity="HIGH",
        description="Java-based template engine injection for RCE via Runtime.exec()"
    ),

    # ═══════════════════════════════════════════════════════════════
    # HTTP REQUEST SMUGGLING
    # ═══════════════════════════════════════════════════════════════

    Rule(
        id="NW-SMUG-001",
        name="HTTP Smuggling CL+TE Conflict",
        pattern=re.compile(
            r"(transfer-encoding\s*:\s*chunked[\s\S]*?content-length\s*:|"
            r"content-length\s*:[\s\S]*?transfer-encoding\s*:\s*chunked)",
            re.IGNORECASE | re.DOTALL
        ),
        attack_type="HTTPSmuggling",
        severity="HIGH",
        description="Both Content-Length and Transfer-Encoding present — CL.TE or TE.CL smuggling"
    ),
    Rule(
        id="NW-SMUG-002",
        name="HTTP Smuggling Obfuscated Transfer-Encoding",
        pattern=re.compile(
            r"transfer-encoding\s*:\s*(xchunked|chunked\s+|identity,\s*chunked|\tchunked)",
            re.IGNORECASE
        ),
        attack_type="HTTPSmuggling",
        severity="HIGH",
        description="Mangled TE header to confuse front-end vs back-end parsing"
    ),
]


# ──────────────────────────────────────────────────────────────────────
#  Helper utilities
# ──────────────────────────────────────────────────────────────────────

def get_rules_by_type(attack_type: str) -> List[Rule]:
    """Return all rules matching a given attack_type."""
    return [r for r in RULES if r.attack_type == attack_type]


def get_rules_by_severity(severity: str) -> List[Rule]:
    """Return all rules at a given severity level."""
    return [r for r in RULES if r.severity == severity]


def list_attack_types() -> List[str]:
    """Return a deduplicated list of all attack types in the ruleset."""
    return list(dict.fromkeys(r.attack_type for r in RULES))
