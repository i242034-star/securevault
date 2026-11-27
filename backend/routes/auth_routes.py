"""
Authentication Routes: Register, Login, Current User Profile, and Key Claim
"""
from flask import Blueprint, request, jsonify, g
import json
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models.database import get_db
from utils.auth import hash_password, verify_password, generate_token, require_auth, verify_token
from utils.rate_limit import login_limiter
from crypto.service import CryptoService

auth_bp = Blueprint("auth", __name__)

ALLOWED_SYSTEM_ROLES = {"user", "admin"}

# Verified against when the username doesn't exist (see login()); its password is random.
_DUMMY_PASSWORD_HASH = hash_password(os.urandom(16).hex())


def _caller_is_admin() -> bool:
    """True when the request carries a valid bearer token belonging to an admin."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return False
    payload = verify_token(auth_header[7:].strip())
    if not payload:
        return False
    conn = get_db()
    try:
        row = conn.execute("SELECT system_role FROM users WHERE id = ?", (payload["user_id"],)).fetchone()
        return bool(row and row["system_role"] == "admin")
    finally:
        conn.close()


@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Enrol a new identity and have the Trusted Authority issue its CP-ABE key.

    Attribute assignment is the Trusted Authority's job, so after bootstrap
    only an administrator may enrol users. Otherwise anyone could self-register
    with "Clearance:Level-3" (or system_role=admin) and the access policy would
    mean nothing. The very first account (empty database) is allowed through
    unauthenticated and is forced to be the admin, so a fresh deployment can
    be bootstrapped.
    """
    conn = get_db()
    try:
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    finally:
        conn.close()
    is_bootstrap = user_count == 0
    if not is_bootstrap and not _caller_is_admin():
        return jsonify({
            "error": "Forbidden",
            "message": "Only the Trusted Authority (an administrator) can enrol users and assign attributes."
        }), 403

    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    role_attr = data.get("role_attr", "Role:Engineer").strip()
    clearance_attr = data.get("clearance_attr", "Clearance:Level-3").strip()
    custom_attributes = data.get("custom_attributes", [])
    system_role = data.get("system_role", "user").strip().lower()

    if not username or not password:
        return jsonify({"error": "ValidationFailed", "message": "Username and password are required."}), 400

    if len(password) < 6:
        return jsonify({"error": "ValidationFailed", "message": "Password must be at least 6 characters."}), 400

    if system_role not in ALLOWED_SYSTEM_ROLES:
        return jsonify({"error": "ValidationFailed", "message": "system_role must be 'user' or 'admin'."}), 400
    if is_bootstrap:
        system_role = "admin"
    if not isinstance(custom_attributes, list) or not all(isinstance(a, str) for a in custom_attributes):
        return jsonify({"error": "ValidationFailed", "message": "custom_attributes must be a list of strings."}), 400

    conn = get_db()
    try:
        # Check if username exists
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            return jsonify({"error": "Conflict", "message": f"Username '{username}' is already taken."}), 409

        # Hash password and insert user
        pwd_hash = hash_password(password)
        cursor = conn.execute(
            """
            INSERT INTO users (username, password_hash, system_role, role_attr, clearance_attr, custom_attributes, pending_key_reissue)
            VALUES (?, ?, ?, ?, ?, ?, 0)
            """,
            (username, pwd_hash, system_role, role_attr, clearance_attr, json.dumps(custom_attributes))
        )
        user_id = cursor.lastrowid
        conn.commit()

        # Automatically issue initial CP-ABE cryptographic key bound to user attributes + current epoch
        crypto_svc = CryptoService.get_instance()
        all_attrs = [role_attr, clearance_attr] + [a for a in custom_attributes if a]
        key_info = crypto_svc.issue_user_key(
            user_id=user_id,
            username=username,
            attributes=all_attrs,
            user_passphrase=password,
            ip_address=request.remote_addr,
            include_epoch=True
        )

        token = generate_token(user_id, username, system_role)

        return jsonify({
            "message": "User registered successfully and CP-ABE key issued.",
            "token": token,
            "user": {
                "id": user_id,
                "username": username,
                "system_role": system_role,
                "role_attr": role_attr,
                "clearance_attr": clearance_attr,
                "custom_attributes": custom_attributes
            },
            "key_info": key_info
        }), 201

    finally:
        conn.close()


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "ValidationFailed", "message": "Username and password are required."}), 400

    client_ip = request.remote_addr or "unknown"

    # Brute-force countermeasure: refuse while this (username, IP) is locked out.
    retry_after = login_limiter.retry_after(username, client_ip)
    if retry_after:
        CryptoService.get_instance().log_audit(
            user_id=None,
            username=username,
            action="AUTH_LOCKOUT",
            status="DENIED",
            details=f"Login refused: too many failed attempts. Retry in {retry_after}s.",
            ip_address=client_ip
        )
        resp = jsonify({
            "error": "TooManyRequests",
            "message": f"Too many failed login attempts. Try again in {retry_after} seconds.",
            "retry_after": retry_after
        })
        resp.headers["Retry-After"] = str(retry_after)
        return resp, 429

    conn = get_db()
    try:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        # Timing side-channel countermeasure: always run one PBKDF2 verification,
        # even for unknown usernames, so response time doesn't reveal which
        # usernames exist (username enumeration).
        stored_hash = user["password_hash"] if user else _DUMMY_PASSWORD_HASH
        password_ok = verify_password(password, stored_hash)
        if not user or not password_ok:
            locked_now = login_limiter.register_failure(username, client_ip)
            # Log failed login attempt
            CryptoService.get_instance().log_audit(
                user_id=None,
                username=username,
                action="AUTH_LOGIN",
                status="FAILED",
                details="Invalid username or password credentials"
                        + (" — lockout triggered" if locked_now else ""),
                ip_address=client_ip
            )
            return jsonify({"error": "Unauthorized", "message": "Invalid username or password."}), 401

        login_limiter.register_success(username, client_ip)

        crypto_svc = CryptoService.get_instance()
        key_reissued_on_login = False

        # Asynchronous key claim on login (Clarification 3):
        # If user has a pending key update, their login password unlocks the new envelope without admin involvement
        if user["pending_key_reissue"] == 1:
            try:
                crypto_svc.claim_pending_key(user["id"], password, request.remote_addr)
                key_reissued_on_login = True
            except Exception as e:
                print(f"[!] Warning: Auto-claiming pending key for {username} failed: {e}")

        # Fetch active key metadata
        active_key = conn.execute(
            "SELECT id, key_version, bound_attributes, issued_at FROM user_keys WHERE user_id = ? AND is_active = 1",
            (user["id"],)
        ).fetchone()

        token = generate_token(user["id"], user["username"], user["system_role"])

        # Log successful login
        crypto_svc.log_audit(
            user_id=user["id"],
            username=user["username"],
            action="AUTH_LOGIN",
            status="SUCCESS",
            details="User logged in successfully" + (" (updated key activated)" if key_reissued_on_login else ""),
            ip_address=request.remote_addr
        )

        custom_attrs = []
        if "custom_attributes" in user.keys() and user["custom_attributes"]:
            try:
                custom_attrs = json.loads(user["custom_attributes"])
            except Exception:
                custom_attrs = []

        return jsonify({
            "message": "Login successful.",
            "token": token,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "system_role": user["system_role"],
                "role_attr": user["role_attr"],
                "clearance_attr": user["clearance_attr"],
                "custom_attributes": custom_attrs,
                "pending_key_reissue": bool(user["pending_key_reissue"] and not key_reissued_on_login)
            },
            "active_key": {
                "id": active_key["id"],
                "key_version": active_key["key_version"],
                "bound_attributes": json.loads(active_key["bound_attributes"]),
                "issued_at": active_key["issued_at"]
            } if active_key else None,
            "key_reissued": key_reissued_on_login
        }), 200

    finally:
        conn.close()


@auth_bp.route("/claim-key", methods=["POST"])
@require_auth
def claim_key():
    """
    Authorized user explicitly claims their pending CP-ABE private key using their own password.
    Administrator never handles or knows user passwords.
    """
    data = request.get_json() or {}
    password = data.get("password", "").strip()

    if not password:
        return jsonify({"error": "ValidationFailed", "message": "Password is required to envelope-encrypt your new key."}), 400

    crypto_svc = CryptoService.get_instance()
    try:
        key_info = crypto_svc.claim_pending_key(g.current_user["id"], password, request.remote_addr)
        return jsonify({
            "message": f"Successfully activated CP-ABE private key v{key_info['version']}.",
            "key_info": key_info
        }), 200
    except ValueError as ve:
        return jsonify({"error": "AuthenticationFailed", "message": str(ve)}), 401
    except Exception as e:
        return jsonify({"error": "KeyIssuanceFailed", "message": str(e)}), 500


@auth_bp.route("/me", methods=["GET"])
@require_auth
def get_current_user():
    user = g.current_user
    conn = get_db()
    try:
        user_row = conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
        active_key = conn.execute(
            "SELECT id, key_version, bound_attributes, issued_at FROM user_keys WHERE user_id = ? AND is_active = 1",
            (user["id"],)
        ).fetchone()

        custom_attrs = []
        if user_row and "custom_attributes" in user_row.keys() and user_row["custom_attributes"]:
            try:
                custom_attrs = json.loads(user_row["custom_attributes"])
            except Exception:
                custom_attrs = []

        return jsonify({
            "user": {
                **user,
                "custom_attributes": custom_attrs,
                "pending_key_reissue": bool(user_row["pending_key_reissue"]) if user_row else False
            },
            "active_key": {
                "id": active_key["id"],
                "key_version": active_key["key_version"],
                "bound_attributes": json.loads(active_key["bound_attributes"]),
                "issued_at": active_key["issued_at"]
            } if active_key else None
        }), 200
    finally:
        conn.close()
