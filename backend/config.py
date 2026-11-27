"""
SecureVault Configuration Module
Defines storage paths, cryptographic authority parameters, and security tokens.

Required Environment Variables (PRODUCTION — FLASK_ENV=production)
==================================================================
  MASTER_KEY_PASSPHRASE   Passphrase used to encrypt the master secret key at
                          rest. Must be a strong, randomly-generated string.

  JWT_SECRET              Secret key used to sign and verify JWT session tokens.
                          Must be a strong, randomly-generated string.

  AUDIT_HMAC_SECRET       Secret key used for the tamper-evident audit log
                          HMAC hash chain. Must be a strong, randomly-generated
                          string.

Optional Environment Variables
==============================
  FLASK_ENV               Set to 'production' to enable the production secret
                          validator (default: 'development').
  CORS_ALLOWED_ORIGINS    Comma-separated list of allowed CORS origins.
  FLASK_HOST              Host to bind the dev server (default: '0.0.0.0').
  FLASK_PORT              Port for the dev server (default: 5000).
  FLASK_DEBUG             Set to 'true' to enable Flask debug mode.

Generating secure secrets (run once, store results in your secrets manager):
  python3 -c "import secrets; print(secrets.token_hex(48))"
"""
import os
import sys

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
KEYS_DIR = os.path.join(STORAGE_DIR, "keys")
ENCRYPTED_DIR = os.path.join(STORAGE_DIR, "encrypted")
ENCRYPTED_DOCS_DIR = ENCRYPTED_DIR  # alias used by app.py and service.py

# Ensure required storage directories exist
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(ENCRYPTED_DIR, exist_ok=True)

# Database file
DATABASE_PATH = os.path.join(STORAGE_DIR, "securevault.db")

# Cryptographic Master Authority paths
MASTER_KEY_PATH = os.path.join(KEYS_DIR, "master_secret_key.enc")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.json")

# ---------------------------------------------------------------------------
# Known insecure default values used only for LOCAL DEVELOPMENT convenience.
# These values MUST NOT be used in a production deployment.
# ---------------------------------------------------------------------------
_DEV_DEFAULTS = {
    "MASTER_KEY_PASSPHRASE": "Authority_Secure_Passphrase_2026!",
    "JWT_SECRET": "SecureVault_JWT_SuperSecret_Key_2026_SemesterProject",
    "AUDIT_HMAC_SECRET": "SecureVault_Audit_HMAC_SecretKey_2026_SemesterProject",
}

# Master authority passphrase (used for encrypting MK at rest)
MASTER_KEY_PASSPHRASE = os.environ.get(
    "MASTER_KEY_PASSPHRASE", _DEV_DEFAULTS["MASTER_KEY_PASSPHRASE"]
)

# Token / Session Secret
JWT_SECRET = os.environ.get("JWT_SECRET", _DEV_DEFAULTS["JWT_SECRET"])
TOKEN_EXPIRATION_HOURS = 24

# Dedicated Audit HMAC Secret for Tamper-Evident Hash Chaining
# Keep outside SQLite database; configurable via environment
AUDIT_HMAC_SECRET = os.environ.get(
    "AUDIT_HMAC_SECRET", _DEV_DEFAULTS["AUDIT_HMAC_SECRET"]
)

# CORS Configuration: explicit allowed origins (no wildcard '*')
DEFAULT_CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
_cors_env = os.environ.get("CORS_ALLOWED_ORIGINS", "").strip()
if _cors_env:
    CORS_ALLOWED_ORIGINS = [origin.strip() for origin in _cors_env.split(",") if origin.strip()]
else:
    CORS_ALLOWED_ORIGINS = DEFAULT_CORS_ORIGINS

# Default Core Access Policy for the project
DEFAULT_CORE_POLICY = "(Role:Engineer OR Role:Manager) AND Clearance:Level-3"

# Maximum upload size (MB) — enforced by Flask's MAX_CONTENT_LENGTH
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "20"))

# Seed demo personas + a sample encrypted document when the database is empty
SEED_DEMO_DATA = os.environ.get("SEED_DEMO_DATA", "true").lower() == "true"

# Flask server settings
HOST = os.environ.get("FLASK_HOST", "0.0.0.0")
PORT = int(os.environ.get("FLASK_PORT", "5000"))
DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Production secret validation
# ---------------------------------------------------------------------------
def _validate_production_secrets() -> None:
    """
    Refuse to start when FLASK_ENV=production and any security-critical secret
    is missing, empty, or still set to a known development default.

    - Never prints secret values.
    - Only runs when explicitly in production mode.
    - Does not generate replacement secrets.
    """
    env = os.environ.get("FLASK_ENV", "development").lower()
    if env != "production":
        return  # Local / development mode — skip validation.

    _secrets_to_check = {
        "MASTER_KEY_PASSPHRASE": MASTER_KEY_PASSPHRASE,
        "JWT_SECRET": JWT_SECRET,
        "AUDIT_HMAC_SECRET": AUDIT_HMAC_SECRET,
    }

    errors = []
    for var_name, value in _secrets_to_check.items():
        if not value:
            errors.append(f"  - {var_name} is missing or empty.")
        elif value == _DEV_DEFAULTS.get(var_name):
            errors.append(
                f"  - {var_name} is set to a known insecure development default."
            )

    if errors:
        # Print the variable *names* but never the values.
        print(
            "\n[FATAL] SecureVault cannot start in production mode with insecure "
            "secrets.\n"
            "The following environment variables must be set to strong, unique "
            "values:\n",
            file=sys.stderr,
        )
        for msg in errors:
            print(msg, file=sys.stderr)
        print(
            "\nSet these variables in your secrets manager or .env file and "
            "restart the service.\n"
            "See the module docstring in config.py for generation instructions.\n",
            file=sys.stderr,
        )
        sys.exit(1)


# Run validation immediately when this module is imported so that the error
# surfaces before any Flask worker accepts connections.
_validate_production_secrets()
