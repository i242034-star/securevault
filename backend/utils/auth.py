"""
Authentication & Authorization Utilities
- PBKDF2-HMAC-SHA256 password hashing with salt.
- Cryptographically signed HMAC-SHA256 bearer tokens.
- Decorators for endpoint authorization.
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import time
from functools import wraps
from flask import request, jsonify, g

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import config
from models.database import get_db


def hash_password(password: str) -> str:
    """
    Hash a password using PBKDF2-HMAC-SHA256 with 100,000 iterations and a random salt.
    """
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    salt_b64 = base64.b64encode(salt).decode('ascii')
    dk_b64 = base64.b64encode(dk).decode('ascii')
    return f"pbkdf2_sha256$100000${salt_b64}${dk_b64}"


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verify a password against a stored PBKDF2 hash using constant-time comparison.
    """
    try:
        parts = stored_hash.split('$')
        if len(parts) != 4 or parts[0] != 'pbkdf2_sha256':
            return False
        iterations = int(parts[1])
        salt = base64.b64decode(parts[2].encode('ascii'))
        expected_dk = base64.b64decode(parts[3].encode('ascii'))

        actual_dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
        return hmac.compare_digest(actual_dk, expected_dk)
    except Exception:
        return False


def generate_token(user_id: int, username: str, system_role: str) -> str:
    """
    Generate an HMAC-SHA256 signed bearer token valid for 24 hours.
    Format: base64(header).base64(payload).signature
    """
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "user_id": user_id,
        "username": username,
        "system_role": system_role,
        "iat": int(time.time()),
        "exp": int(time.time()) + (config.TOKEN_EXPIRATION_HOURS * 3600)
    }

    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode('utf-8')).decode('ascii').rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).decode('ascii').rstrip('=')
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')

    signature = hmac.new(config.JWT_SECRET.encode('utf-8'), signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode('ascii').rstrip('=')

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_token(token: str) -> dict:
    """
    Verify and decode a signed bearer token. Returns payload dict or None.
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts

        # Verify signature
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        expected_sig = hmac.new(config.JWT_SECRET.encode('utf-8'), signing_input, hashlib.sha256).digest()
        expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode('ascii').rstrip('=')

        if not hmac.compare_digest(sig_b64, expected_sig_b64):
            return None

        # Decode payload (add padding back)
        rem = len(payload_b64) % 4
        if rem > 0:
            payload_b64 += '=' * (4 - rem)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode('ascii')).decode('utf-8'))

        # Check expiration
        if payload.get("exp", 0) < time.time():
            return None

        return payload
    except Exception:
        return None


def require_auth(f):
    """
    Flask decorator: Enforces that the request contains a valid Authorization Bearer token.
    Attaches g.current_user (dict from DB).
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Unauthorized", "message": "Missing or malformed Authorization header."}), 401

        token = auth_header[7:].strip()
        payload = verify_token(token)
        if not payload:
            return jsonify({"error": "Unauthorized", "message": "Invalid or expired session token."}), 401

        # Look up user in database
        conn = get_db()
        user = conn.execute("SELECT id, username, system_role, role_attr, clearance_attr FROM users WHERE id = ?", (payload["user_id"],)).fetchone()
        conn.close()

        if not user:
            return jsonify({"error": "Unauthorized", "message": "User account no longer exists."}), 401

        g.current_user = dict(user)
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """
    Flask decorator: Enforces that the current authenticated user has system_role == 'admin'.
    """
    @wraps(f)
    @require_auth
    def decorated(*args, **kwargs):
        if g.current_user.get("system_role") != "admin":
            return jsonify({"error": "Forbidden", "message": "Administrator privileges required for this action."}), 403
        return f(*args, **kwargs)
    return decorated
