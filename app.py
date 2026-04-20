"""
app.py
NIGHTWATCH Flask Application Factory — Phase 4

Added: SQLite persistent storage via storage/db.py
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

    app.config["SECRET_KEY"]      = os.getenv("API_SECRET_KEY", "nightwatch-dev")
    app.config["JSON_SORT_KEYS"]  = False

    CORS(app, resources={r"/api/*": {"origins": "*"}})

    logging.basicConfig(
        stream=sys.stdout,
        level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # ── Phase 4: Initialize database ─────────────────────────────
    from storage.db import init_db
    init_db(app)

    # ── Register blueprints ───────────────────────────────────────
    from api.routes import api_bp
    from api.auth import auth_bp
    from api.proxy import proxy_bp

    app.register_blueprint(api_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(proxy_bp)   # catch-all — must be last

    return app


if __name__ == "__main__":
    host = os.getenv("WAF_HOST", "0.0.0.0")
    port = int(os.getenv("WAF_PORT", 5000))

    print(f"""
╔══════════════════════════════════════════════════════╗
║         🦉 NIGHTWATCH WAF — Starting Up             ║
╠══════════════════════════════════════════════════════╣
║  WAF Proxy   : http://{host}:{port}
║  Analysis API: http://{host}:{port}/api/
║  Target App  : {os.getenv('TARGET_URL', 'http://127.0.0.1:5001')}
║  Database    : nightwatch.db (SQLite)
╚══════════════════════════════════════════════════════╝
    """)

    application = create_app()
    application.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    host = os.getenv("WAF_HOST", "0.0.0.0")
    port = int(os.getenv("WAF_PORT", 5000))
    application = create_app()
    application.run(host=host, port=port, debug=False)
