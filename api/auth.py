"""
api/auth.py
NIGHTWATCH JWT Authentication

Endpoints:
  POST /auth/login    — username + password → JWT token
  POST /auth/refresh  — valid token → new token
  GET  /auth/status   — check if token is valid
  POST /auth/logout   — client-side (token just gets discarded)

Usage (protect a route):
  from api.auth import jwt_required

  @api_bp.route("/logs")
  @jwt_required
  def get_logs():
      ...
"""

import os
import jwt
import bcrypt
import datetime
from functools import wraps
from flask import Blueprint, request, jsonify, g
from dotenv import load_dotenv

load_dotenv()

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

# ── Config ────────────────────────────────────────────────────────────
JWT_SECRET  = os.getenv("JWT_SECRET_KEY", "nightwatch-jwt-secret-change-this")
JWT_EXPIRY  = int(os.getenv("JWT_EXPIRY_HOURS", "1"))
ADMIN_USER  = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASS  = os.getenv("ADMIN_PASSWORD", "nightwatch2024")
ALGORITHM   = "HS256"

# Hash the password at startup (bcrypt is slow by design — do it once)
_ADMIN_PASS_HASH = bcrypt.hashpw(ADMIN_PASS.encode(), bcrypt.gensalt())


# ─────────────────────────────────────────────────────────────────────
#  TOKEN HELPERS
# ─────────────────────────────────────────────────────────────────────

def _generate_token(username: str) -> str:
    """Generate a signed JWT token valid for JWT_EXPIRY hours."""
    import uuid
    payload = {
        "sub":  username,
        "iat":  datetime.datetime.utcnow(),
        "exp":  datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXPIRY),
        "role": "admin",
        "jti":  str(uuid.uuid4()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


def _verify_token(token: str) -> dict:
    """
    Verify and decode a JWT token.
    Returns the decoded payload or raises jwt.InvalidTokenError.
    """
    return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])


def _get_token_from_request() -> str:
    """Extract token from Authorization: Bearer <token> header."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    # Also check cookie for dashboard use
    return request.cookies.get("nw_token", "")


# ─────────────────────────────────────────────────────────────────────
#  DECORATOR
# ─────────────────────────────────────────────────────────────────────

def jwt_required(f):
    """
    Decorator to protect API routes with JWT auth.

    Usage:
        @api_bp.route("/protected")
        @jwt_required
        def protected():
            return jsonify({"user": g.current_user})
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _get_token_from_request()

        if not token:
            return jsonify({
                "error":   "Authentication required",
                "message": "Provide a JWT token in Authorization: Bearer <token> header"
            }), 401

        try:
            payload = _verify_token(token)
            g.current_user = payload.get("sub")
            g.token_payload = payload
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired", "message": "Please log in again"}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({"error": "Invalid token", "message": str(e)}), 401

        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Login with username + password.
    Returns a JWT token on success.

    Body: {"username": "admin", "password": "..."}
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    # Constant-time username check
    if username != ADMIN_USER:
        return jsonify({"error": "Invalid credentials"}), 401

    # bcrypt password verification (timing-safe)
    if not bcrypt.checkpw(password.encode(), _ADMIN_PASS_HASH):
        return jsonify({"error": "Invalid credentials"}), 401

    token = _generate_token(username)

    return jsonify({
        "token":      token,
        "expires_in": JWT_EXPIRY * 3600,
        "token_type": "Bearer",
        "username":   username,
    })


@auth_bp.route("/refresh", methods=["POST"])
@jwt_required
def refresh():
    """Exchange a valid (non-expired) token for a new one."""
    new_token = _generate_token(g.current_user)
    return jsonify({
        "token":      new_token,
        "expires_in": JWT_EXPIRY * 3600,
        "token_type": "Bearer",
    })


@auth_bp.route("/status", methods=["GET"])
def status():
    """Check if the current token is valid."""
    token = _get_token_from_request()
    if not token:
        return jsonify({"authenticated": False, "message": "No token provided"})

    try:
        payload = _verify_token(token)
        return jsonify({
            "authenticated": True,
            "username":      payload.get("sub"),
            "expires_at":    payload.get("exp"),
        })
    except jwt.ExpiredSignatureError:
        return jsonify({"authenticated": False, "message": "Token expired"})
    except jwt.InvalidTokenError:
        return jsonify({"authenticated": False, "message": "Invalid token"})


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """
    Logout — JWT is stateless so we just tell the client to discard the token.
    Phase 8 enhancement: a token blacklist could be added here.
    """
    return jsonify({"message": "Logged out successfully"})
