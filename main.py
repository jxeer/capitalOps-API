"""
CapitalOps API - Application Entry Point

Starts the Flask JSON API server on port 3001. This is the main entry point
for both development (python main.py) and the Replit workflow.

The create_app() factory in app/__init__.py handles all initialization
including database setup, blueprint registration, and demo data seeding.

The React frontend (capitalops-web) runs on port 5000 via Vite and
proxies /api requests to this backend on port 3001.
"""

import os
from app import create_app

app = create_app()

if __name__ == "__main__":
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=3001, debug=debug)
