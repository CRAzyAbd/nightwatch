"""
storage/db.py
NIGHTWATCH Persistent Storage Layer

Tables:
  request_logs  — every request analyzed by the WAF
  blocked_ips   — IP blocklist with TTL (auto-expiry)
  stats_daily   — daily aggregated counters

Uses SQLite by default (zero setup).
Switch to PostgreSQL in production by changing DATABASE_URL in .env:
  DATABASE_URL=postgresql://user:pass@localhost/nightwatch
"""

import os
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

db = SQLAlchemy()

# ─────────────────────────────────────────────────────────────────────
#  MODELS (database tables)
# ─────────────────────────────────────────────────────────────────────

class RequestLog(db.Model):
    """
    One row per HTTP request analyzed by NIGHTWATCH.
    Stores everything needed for forensics and dashboard charts.
    """
    __tablename__ = "request_logs"

    id            = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp     = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Request info
    ip            = db.Column(db.String(45),  nullable=False, index=True)   # IPv6 max = 45 chars
    method        = db.Column(db.String(10),  nullable=False)
    url           = db.Column(db.String(500), nullable=False)
    user_agent    = db.Column(db.String(300), nullable=True)

    # WAF decision
    verdict       = db.Column(db.String(10),  nullable=False, index=True)   # BLOCK/MONITOR/ALLOW
    risk_score    = db.Column(db.Float,       nullable=False)
    regex_score   = db.Column(db.Float,       nullable=True)
    ml_score      = db.Column(db.Float,       nullable=True)

    # Attack details (JSON strings)
    attack_types  = db.Column(db.Text, nullable=True)   # JSON list e.g. '["SQLi","XSS"]'
    rules_fired   = db.Column(db.Text, nullable=True)   # JSON list of rule IDs

    # ML ensemble details
    ml_agreement  = db.Column(db.String(30), nullable=True)   # "unanimous_attack" etc.

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id":           self.id,
            "timestamp":    self.timestamp.isoformat(),
            "ip":           self.ip,
            "method":       self.method,
            "url":          self.url,
            "user_agent":   self.user_agent,
            "verdict":      self.verdict,
            "risk_score":   self.risk_score,
            "regex_score":  self.regex_score,
            "ml_score":     self.ml_score,
            "attack_types": json.loads(self.attack_types) if self.attack_types else [],
            "rules_fired":  json.loads(self.rules_fired)  if self.rules_fired  else [],
            "ml_agreement": self.ml_agreement,
        }


class BlockedIP(db.Model):
    """
    Persistent IP blocklist.
    Replaces the in-memory dict in core/threat_intel.py.
    Supports TTL — IPs auto-expire after a set duration.
    """
    __tablename__ = "blocked_ips"

    id         = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip         = db.Column(db.String(45),  nullable=False, unique=True, index=True)
    reason     = db.Column(db.String(200), nullable=False, default="manual")
    blocked_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)    # None = permanent block
    auto_block = db.Column(db.Boolean, default=False)     # True = blocked by WAF automatically

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at.replace(tzinfo=timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id":         self.id,
            "ip":         self.ip,
            "reason":     self.reason,
            "blocked_at": self.blocked_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "auto_block": self.auto_block,
            "permanent":  self.expires_at is None,
        }


class StatsDaily(db.Model):
    """
    Daily aggregated statistics.
    One row per day — updated at request time.
    Powers the dashboard charts.
    """
    __tablename__ = "stats_daily"

    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    date         = db.Column(db.Date, nullable=False, unique=True, index=True)
    total        = db.Column(db.Integer, default=0)
    blocked      = db.Column(db.Integer, default=0)
    monitored    = db.Column(db.Integer, default=0)
    allowed      = db.Column(db.Integer, default=0)

    # Attack type breakdown (JSON dict e.g. {"SQLi": 5, "XSS": 2})
    attack_breakdown = db.Column(db.Text, default="{}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "date":             self.date.isoformat(),
            "total":            self.total,
            "blocked":          self.blocked,
            "monitored":        self.monitored,
            "allowed":          self.allowed,
            "attack_breakdown": json.loads(self.attack_breakdown or "{}"),
        }


# ─────────────────────────────────────────────────────────────────────
#  DATABASE OPERATIONS
# ─────────────────────────────────────────────────────────────────────

def init_db(app):
    """
    Initialize the database with the Flask app.
    Creates all tables if they don't exist.
    Call this once in app.py create_app().
    """
    db_path = os.getenv("DATABASE_URL", "sqlite:///nightwatch.db")
    app.config["SQLALCHEMY_DATABASE_URI"]        = db_path
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"]      = {
        "pool_pre_ping": True,   # auto-reconnect on stale connections
    }

    db.init_app(app)

    with app.app_context():
        db.create_all()
        print(f"[Storage] Database ready: {db_path}")


def log_request(result: Dict[str, Any], request_data: Dict[str, Any]) -> None:
    """
    Save one analyzed request to the database.
    Called by the proxy after every analysis.
    """
    try:
        matched_rules = result.get("matched_rules", [])
        attack_types  = list(set(r["attack_type"] for r in matched_rules))
        rules_fired   = [r["id"] for r in matched_rules]

        ml_result   = result.get("ml_result") or {}
        ml_agreement = ml_result.get("agreement")

        headers    = request_data.get("headers", {})
        user_agent = headers.get("User-Agent") or headers.get("user-agent", "")

        log = RequestLog(
            ip           = request_data.get("ip", "unknown"),
            method       = request_data.get("method", "GET"),
            url          = request_data.get("url", "/")[:500],
            user_agent   = str(user_agent)[:300],
            verdict      = result.get("verdict", "ALLOW"),
            risk_score   = result.get("risk_score", 0.0),
            regex_score  = result.get("regex_score", 0.0),
            ml_score     = result.get("ml_score", 0.0),
            attack_types = json.dumps(attack_types),
            rules_fired  = json.dumps(rules_fired),
            ml_agreement = ml_agreement,
        )
        db.session.add(log)

        # Update daily stats
        _update_daily_stats(result, attack_types)

        db.session.commit()

    except Exception as e:
        db.session.rollback()
        print(f"[Storage] Warning: could not log request: {e}")


def _update_daily_stats(result: Dict[str, Any], attack_types: List[str]) -> None:
    """Upsert today's stats row."""
    today = datetime.now(timezone.utc).date()
    row   = StatsDaily.query.filter_by(date=today).first()

    if not row:
        row = StatsDaily(date=today, attack_breakdown="{}")
        db.session.add(row)

    row.total    = (row.total    or 0) + 1
    verdict = result.get("verdict", "ALLOW")
    if verdict == "BLOCK":
        row.blocked  = (row.blocked  or 0) + 1
    elif verdict == "MONITOR":
        row.monitored = (row.monitored or 0) + 1
    else:
        row.allowed  = (row.allowed  or 0) + 1

    # Update attack type breakdown
    breakdown = json.loads(row.attack_breakdown or "{}")
    for atype in attack_types:
        breakdown[atype] = breakdown.get(atype, 0) + 1
    row.attack_breakdown = json.dumps(breakdown)


# ─────────────────────────────────────────────────────────────────────
#  IP BLOCKLIST OPERATIONS
# ─────────────────────────────────────────────────────────────────────

def db_block_ip(ip: str, reason: str = "manual",
                ttl_minutes: Optional[int] = None,
                auto: bool = False) -> None:
    """
    Add or update an IP in the persistent blocklist.

    Args:
        ip:          The IP to block
        reason:      Why it was blocked
        ttl_minutes: Auto-expiry in minutes (None = permanent)
        auto:        True if blocked automatically by WAF
    """
    try:
        expires_at = None
        if ttl_minutes:
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)

        existing = BlockedIP.query.filter_by(ip=ip).first()
        if existing:
            existing.reason     = reason
            existing.blocked_at = datetime.now(timezone.utc)
            existing.expires_at = expires_at
            existing.auto_block = auto
        else:
            entry = BlockedIP(
                ip=ip, reason=reason,
                expires_at=expires_at, auto_block=auto
            )
            db.session.add(entry)

        db.session.commit()
        print(f"[Storage] ⛔ Blocked: {ip} | reason={reason} | ttl={ttl_minutes}min")

    except Exception as e:
        db.session.rollback()
        print(f"[Storage] Warning: could not block IP {ip}: {e}")


def db_unblock_ip(ip: str) -> bool:
    """Remove an IP from the persistent blocklist. Returns True if found."""
    try:
        entry = BlockedIP.query.filter_by(ip=ip).first()
        if entry:
            db.session.delete(entry)
            db.session.commit()
            print(f"[Storage] ✅ Unblocked: {ip}")
            return True
        return False
    except Exception as e:
        db.session.rollback()
        print(f"[Storage] Warning: could not unblock IP {ip}: {e}")
        return False


def db_check_ip(ip: str) -> Dict[str, Any]:
    """
    Check if an IP is blocked.
    Automatically removes expired blocks.
    """
    try:
        entry = BlockedIP.query.filter_by(ip=ip).first()
        if not entry:
            return {"ip": ip, "is_blocked": False}

        if entry.is_expired():
            db.session.delete(entry)
            db.session.commit()
            return {"ip": ip, "is_blocked": False, "note": "block expired and removed"}

        return {
            "ip":         ip,
            "is_blocked": True,
            "reason":     entry.reason,
            "blocked_at": entry.blocked_at.isoformat(),
            "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
        }
    except Exception as e:
        print(f"[Storage] Warning: IP check failed for {ip}: {e}")
        return {"ip": ip, "is_blocked": False}


def db_get_blocked_ips() -> List[Dict]:
    """Return all currently active (non-expired) blocked IPs."""
    try:
        entries = BlockedIP.query.all()
        active  = []
        expired = []

        for e in entries:
            if e.is_expired():
                expired.append(e)
            else:
                active.append(e.to_dict())

        # Clean up expired entries
        for e in expired:
            db.session.delete(e)
        if expired:
            db.session.commit()

        return active
    except Exception as e:
        print(f"[Storage] Warning: could not fetch blocklist: {e}")
        return []


# ─────────────────────────────────────────────────────────────────────
#  QUERY HELPERS  (used by /api/logs and /api/stats)
# ─────────────────────────────────────────────────────────────────────

def get_recent_logs(limit: int = 100, verdict: Optional[str] = None) -> List[Dict]:
    """Return the most recent request logs, optionally filtered by verdict."""
    try:
        q = RequestLog.query.order_by(RequestLog.timestamp.desc())
        if verdict:
            q = q.filter_by(verdict=verdict.upper())
        return [row.to_dict() for row in q.limit(limit).all()]
    except Exception as e:
        print(f"[Storage] Warning: could not fetch logs: {e}")
        return []


def get_stats_last_n_days(n: int = 7) -> List[Dict]:
    """Return daily stats for the last N days."""
    try:
        since = datetime.now(timezone.utc).date() - timedelta(days=n)
        rows  = (StatsDaily.query
                 .filter(StatsDaily.date >= since)
                 .order_by(StatsDaily.date.asc())
                 .all())
        return [r.to_dict() for r in rows]
    except Exception as e:
        print(f"[Storage] Warning: could not fetch daily stats: {e}")
        return []


def get_top_attacking_ips(limit: int = 10) -> List[Dict]:
    """Return the IPs with the most BLOCK verdicts."""
    try:
        rows = (db.session.query(
                    RequestLog.ip,
                    db.func.count(RequestLog.id).label("count")
                )
                .filter(RequestLog.verdict == "BLOCK")
                .group_by(RequestLog.ip)
                .order_by(db.func.count(RequestLog.id).desc())
                .limit(limit)
                .all())
        return [{"ip": r.ip, "blocked_requests": r.count} for r in rows]
    except Exception as e:
        print(f"[Storage] Warning: could not fetch top attackers: {e}")
        return []
