"""
wsgi.py — Production WSGI Entrypoint for SecureVault
Runs under Gunicorn on Render / Cloud container hosting.
Ensures database and cryptographic authority services are initialized once upon worker boot.
"""
import os
import sys

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app import create_app, initialise_services

app = create_app()
initialise_services(app)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", os.environ.get("FLASK_PORT", 5000)))
    app.run(host="0.0.0.0", port=port)
