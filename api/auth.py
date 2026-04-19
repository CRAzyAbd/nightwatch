"""
api/auth.py
NIGHTWATCH JWT Authentication

Phase 3: stub only — routes registered but JWT not enforced yet.
Phase 8: full JWT login, token refresh, protected dashboard routes.
"""

from flask import Blueprint, jsonify

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/status", methods=["GET"])
def auth_status():
    """Auth status — Phase 8 will return token validity here."""
    return jsonify({
        "authenticated": False,
        "message": "JWT auth not yet implemented (Phase 8)",
    })
