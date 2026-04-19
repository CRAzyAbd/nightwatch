"""
app.py
NIGHTWATCH Flask Application Factory

Creates and configures the Flask app with:
  - WAF proxy (catches all traffic, proxies to backend)
  - Analysis API (/api/*)
  - Auth routes (/auth/*)
  - CORS for future React dashboard
  - Structured logging
"""

import os
import logging
import sys
from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()


def create_app() -> Flask:
    app = Flask(__name__)

    # ── Config ────────────────────────────────────────────────────
    app.config["SECRET_KEY"] = os.getenv("API_SECRET_KEY", "nightwatch-dev")
    app.config["JSON_SORT_KEYS"] = False

    # ── CORS (allow React dashboard on port 3000 in dev) ─────────
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # ── Logging ───────────────────────────────────────────────────
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        stream=sys.stdout,
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # ── Register blueprints ───────────────────────────────────────
    from api.routes import api_bp
    from api.auth import auth_bp
    from api.proxy import proxy_bp

    app.register_blueprint(api_bp)    # /api/*
    app.register_blueprint(auth_bp)   # /auth/*
    app.register_blueprint(proxy_bp)  # /* (catch-all proxy — must be last)

    return app


if __name__ == "__main__":
    import os
    host = os.getenv("WAF_HOST", "0.0.0.0")
    port = int(os.getenv("WAF_PORT", 5000))

    print(f"""
╔══════════════════════════════════════════════════════╗
║         🦉 NIGHTWATCH WAF — Starting Up             ║
╠══════════════════════════════════════════════════════╣
║  WAF Proxy   : http://{host}:{port}                  
║  Analysis API: http://{host}:{port}/api/             
║  Target App  : {os.getenv('TARGET_URL', 'http://127.0.0.1:5001')}            
╚══════════════════════════════════════════════════════╝
    """)

    application = create_app()
    application.run(host=host, port=port, debug=False)
