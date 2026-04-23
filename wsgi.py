"""
wsgi.py
Gunicorn entry point for NIGHTWATCH.

Usage:
  gunicorn --workers 4 --bind 0.0.0.0:8000 wsgi:application
"""
from app import create_app

application = create_app()

if __name__ == "__main__":
    application.run()
