"""
app.py — SecureVault Flask application entry point
Run with:  python3 app.py
"""

import os
import sys

# Ensure the backend directory is on PYTHONPATH so sub-packages resolve correctly
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from flask import Flask, jsonify
from flask_cors import CORS

from config import (
    JWT_SECRET,
    DATABASE_PATH,
    MASTER_KEY_PATH,
    PUBLIC_KEY_PATH,
    ENCRYPTED_DOCS_DIR,
    KEYS_DIR,
    HOST,
    PORT,
    DEBUG,
    CORS_ALLOWED_ORIGINS,
    MAX_UPLOAD_MB,
    SEED_DEMO_DATA,
)
from models.database import init_db
from routes import auth_bp, admin_bp, document_bp, audit_bp, attack_bp
from crypto.service import CryptoService


def create_app() -> Flask:
    """Application factory."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = JWT_SECRET
    # Cap request bodies (uploads are read fully into memory for encryption)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

    # Secure CORS allowlist (wildcard '*' removed; accepts explicit frontend origins)
    CORS(
        app,
        resources={r"/api/*": {"origins": CORS_ALLOWED_ORIGINS}},
        supports_credentials=True,
    )

    # ------------------------------------------------------------------ #
    #  Register blueprints                                                 #
    # ------------------------------------------------------------------ #
    app.register_blueprint(auth_bp,      url_prefix="/api/auth")
    app.register_blueprint(admin_bp,     url_prefix="/api/admin")
    app.register_blueprint(document_bp,  url_prefix="/api/documents")
    app.register_blueprint(audit_bp,     url_prefix="/api/audit")
    app.register_blueprint(attack_bp,    url_prefix="/api/attacks")

    # ------------------------------------------------------------------ #
    #  Health-check endpoint                                               #
    # ------------------------------------------------------------------ #
    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "service": "SecureVault"}), 200

    # ------------------------------------------------------------------ #
    #  Generic error handlers                                              #
    # ------------------------------------------------------------------ #
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(413)
    def too_large(e):
        return jsonify({"error": "PayloadTooLarge", "message": f"Uploads are limited to {MAX_UPLOAD_MB} MB."}), 413

    @app.errorhandler(500)
    def internal_error(e):
        # Don't leak stack/exception details to clients outside debug mode.
        body = {"error": "Internal server error"}
        if DEBUG:
            body["detail"] = str(e)
        return jsonify(body), 500

    return app


def initialise_services(app: Flask) -> None:
    """
    Initialise the database and crypto service inside the application context.
    Called once at startup.
    """
    with app.app_context():
        # Create storage directories if missing
        os.makedirs(ENCRYPTED_DOCS_DIR, exist_ok=True)
        os.makedirs(KEYS_DIR, exist_ok=True)

        # Initialise SQLite schema
        init_db()
        print("[*] Database initialised.")

        # Initialise / load Trusted Authority (generates or loads MK+PK)
        try:
            svc = CryptoService.get_instance()
            purged = svc.cleanup_unreferenced_files()
            if purged > 0:
                print(f"[*] Crash recovery: purged {purged} orphaned/unreferenced ciphertext files.")
            print("[*] CryptoService ready. Authority public key loaded.")
        except Exception as exc:
            print(f"[!] CryptoService initialisation error: {exc}", file=sys.stderr)
            raise

        # Fresh deployment (e.g. Render's ephemeral disk after a restart):
        # enrol the demo personas and encrypt a sample document so the live
        # demo works immediately. Disable with SEED_DEMO_DATA=false.
        if SEED_DEMO_DATA and not app.config.get("TESTING"):
            from seed_data import seed_if_empty
            if seed_if_empty():
                print("[*] Empty database detected: demo users and sample document seeded.")


if __name__ == "__main__":
    flask_app = create_app()
    initialise_services(flask_app)

    print(f"\n{'='*55}")
    print(f"  SecureVault backend running on http://{HOST}:{PORT}")
    print(f"  Debug mode : {DEBUG}")
    print(f"  DB path    : {DATABASE_PATH}")
    print(f"  MK path    : {MASTER_KEY_PATH}")
    print(f"{'='*55}\n")

    flask_app.run(host=HOST, port=PORT, debug=DEBUG)
