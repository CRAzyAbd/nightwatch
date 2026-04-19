"""
target_app.py
NIGHTWATCH — Vulnerable Target Application

This is a deliberately insecure Flask app for testing NIGHTWATCH.
It echoes back whatever you send it so you can verify:
  - Attacks sent directly to port 5001 → succeed (no WAF)
  - Attacks sent through WAF on port 5000 → blocked

DO NOT expose port 5001 publicly.
"""

from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/")
def index():
    return jsonify({"message": "Vulnerable Target App", "port": 5001})


@app.route("/search")
def search():
    """Echoes the query param — vulnerable to XSS/SQLi in a real app."""
    q = request.args.get("q", "")
    return jsonify({"query": q, "results": [], "note": "Target received this safely"})


@app.route("/api/data")
def api_data():
    """Returns whatever params are sent — simulates a real API endpoint."""
    return jsonify({"params": dict(request.args), "headers_received": True})


@app.route("/api/login", methods=["POST"])
def login():
    """Login endpoint — echoes credentials (for testing only)."""
    data = request.get_json(silent=True) or {}
    return jsonify({"received": data, "status": "target reached"})


@app.route("/ping")
def ping():
    """Simulates a ping endpoint vulnerable to CMDi."""
    host = request.args.get("host", "")
    return jsonify({"host": host, "status": "target received ping request"})


@app.route("/fetch")
def fetch():
    """Simulates a URL fetch endpoint vulnerable to SSRF."""
    url = request.args.get("url", "")
    return jsonify({"url": url, "status": "target received fetch request"})


@app.route("/template")
def template():
    """Simulates a template endpoint vulnerable to SSTI."""
    t = request.args.get("t", "")
    return jsonify({"template": t, "status": "target received template request"})


if __name__ == "__main__":
    print("🎯 Vulnerable Target App running on port 5001")
    print("   Direct access (no WAF): http://127.0.0.1:5001")
    print("   Protected access (WAF): http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5001, debug=False)
