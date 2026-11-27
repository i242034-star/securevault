"""
Admin Routes: User Attribute Management, Cryptographic Key Management,
and Phase 4 Epoch-Based Revocation Lifecycle.
"""
from flask import Blueprint, request, jsonify, g
import json
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models.database import get_db
from utils.auth import require_admin
from crypto.service import CryptoService
from crypto.hybrid_cipher import AccessDeniedError, TamperError

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/users", methods=["GET"])
@require_admin
def list_users():
    """
    List all registered users, their roles, clearance, custom attributes,
    active key details, and pending key reissuance status.
    """
    conn = get_db()
    try:
        users = conn.execute("""
            SELECT u.id, u.username, u.system_role, u.role_attr, u.clearance_attr,
                   u.custom_attributes, u.pending_key_reissue, u.created_at,
                   k.key_version, k.bound_attributes, k.issued_at
            FROM users u
            LEFT JOIN user_keys k ON u.id = k.user_id AND k.is_active = 1
            ORDER BY u.id ASC
        """).fetchall()

        results = []
        for u in users:
            custom_attrs = []
            if "custom_attributes" in u.keys() and u["custom_attributes"]:
                try:
                    custom_attrs = json.loads(u["custom_attributes"])
                except Exception:
                    custom_attrs = []

            results.append({
                "id": u["id"],
                "username": u["username"],
                "system_role": u["system_role"],
                "role_attr": u["role_attr"],
                "clearance_attr": u["clearance_attr"],
                "custom_attributes": custom_attrs,
                "pending_key_reissue": bool(u["pending_key_reissue"]),
                "created_at": u["created_at"],
                "active_key": {
                    "version": u["key_version"],
                    "bound_attributes": json.loads(u["bound_attributes"]) if u["bound_attributes"] else None,
                    "issued_at": u["issued_at"]
                } if u["key_version"] else None
            })

        return jsonify({"users": results}), 200
    finally:
        conn.close()


@admin_bp.route("/users/<int:user_id>/attributes", methods=["PUT"])
@require_admin
def update_user_attributes(user_id: int):
    """
    Administrator modifies a user's attributes (roles, clearance, or custom tags).
    In accordance with zero-knowledge key security, the administrator does NOT need
    to know the user's password. The user is marked with pending_key_reissue=1 so they
    can claim their key asynchronously with their own password upon authentication.
    (If user_passphrase is provided by an automated test script, it is issued immediately).
    """
    data = request.get_json() or {}
    new_role = data.get("role_attr")
    new_clearance = data.get("clearance_attr")
    custom_attributes = data.get("custom_attributes")
    user_passphrase = data.get("user_passphrase")  # Optional

    conn = get_db()
    try:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return jsonify({"error": "NotFound", "message": f"User #{user_id} does not exist."}), 404

        old_role = user["role_attr"]
        old_clearance = user["clearance_attr"]

        role_to_set = new_role.strip() if new_role else old_role
        clearance_to_set = new_clearance.strip() if new_clearance else old_clearance

        # Custom attributes handling
        if custom_attributes is not None:
            custom_attrs_list = [a.strip() for a in custom_attributes if a and a.strip()]
        else:
            try:
                custom_attrs_list = json.loads(user["custom_attributes"]) if "custom_attributes" in user.keys() and user["custom_attributes"] else []
            except Exception:
                custom_attrs_list = []

        all_updated_attrs = [role_to_set, clearance_to_set] + custom_attrs_list

        crypto_svc = CryptoService.get_instance()
        key_info = None

        if user_passphrase:
            # Synchronous reissue if passphrase provided
            conn.execute(
                "UPDATE users SET role_attr = ?, clearance_attr = ?, custom_attributes = ?, pending_key_reissue = 0 WHERE id = ?",
                (role_to_set, clearance_to_set, json.dumps(custom_attrs_list), user_id)
            )
            conn.commit()

            key_info = crypto_svc.issue_user_key(
                user_id=user_id,
                username=user["username"],
                attributes=all_updated_attrs,
                user_passphrase=user_passphrase,
                ip_address=request.remote_addr,
                include_epoch=True
            )
        else:
            # Asynchronous pending reissuance (zero-knowledge admin model)
            conn.execute(
                "UPDATE users SET role_attr = ?, clearance_attr = ?, custom_attributes = ?, pending_key_reissue = 1 WHERE id = ?",
                (role_to_set, clearance_to_set, json.dumps(custom_attrs_list), user_id)
            )
            conn.commit()

        # Log audit trail
        crypto_svc.log_audit(
            user_id=g.current_user["id"],
            username=g.current_user["username"],
            action="ATTRIBUTE_CHANGE",
            status="SUCCESS",
            details=f"Admin updated '{user['username']}' attributes: role='{role_to_set}', clearance='{clearance_to_set}', custom={custom_attrs_list}." +
                    (f" Issued key v{key_info['version']}." if key_info else " Marked key reissue pending."),
            ip_address=request.remote_addr
        )

        return jsonify({
            "message": f"User attributes updated for '{user['username']}'.",
            "user_id": user_id,
            "username": user["username"],
            "role_attr": role_to_set,
            "clearance_attr": clearance_to_set,
            "custom_attributes": custom_attrs_list,
            "pending_key_reissue": (key_info is None),
            "key_info": key_info
        }), 200

    finally:
        conn.close()


@admin_bp.route("/users/<int:user_id>/reissue-key", methods=["POST"])
@require_admin
def reissue_user_key(user_id: int):
    """
    Force key reissuance for a user.
    If user_passphrase is provided, issues immediately; otherwise marks pending_key_reissue=1.
    """
    data = request.get_json() or {}
    user_passphrase = data.get("user_passphrase")

    conn = get_db()
    try:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return jsonify({"error": "NotFound", "message": f"User #{user_id} does not exist."}), 404

        custom_attrs = []
        if "custom_attributes" in user.keys() and user["custom_attributes"]:
            try:
                custom_attrs = json.loads(user["custom_attributes"])
            except Exception:
                custom_attrs = []

        all_attrs = [user["role_attr"], user["clearance_attr"]] + custom_attrs
        crypto_svc = CryptoService.get_instance()

        if user_passphrase:
            key_info = crypto_svc.issue_user_key(
                user_id=user_id,
                username=user["username"],
                attributes=all_attrs,
                user_passphrase=user_passphrase,
                ip_address=request.remote_addr,
                include_epoch=True
            )
            return jsonify({
                "message": f"Cryptographic key re-issued successfully for '{user['username']}'.",
                "key_info": key_info
            }), 200
        else:
            conn.execute("UPDATE users SET pending_key_reissue = 1 WHERE id = ?", (user_id,))
            conn.commit()
            return jsonify({
                "message": f"Key re-issuance scheduled for '{user['username']}'. User will claim with their password.",
                "pending_key_reissue": True
            }), 200

    finally:
        conn.close()


@admin_bp.route("/users/<int:user_id>/keys", methods=["GET"])
@require_admin
def get_user_key_history(user_id: int):
    """
    Inspect the key version history for a user (demonstrating key replacement).
    """
    conn = get_db()
    try:
        keys = conn.execute(
            "SELECT id, key_version, bound_attributes, is_active, issued_at FROM user_keys WHERE user_id = ? ORDER BY key_version DESC",
            (user_id,)
        ).fetchall()

        results = []
        for k in keys:
            results.append({
                "id": k["id"],
                "version": k["key_version"],
                "bound_attributes": json.loads(k["bound_attributes"]),
                "is_active": bool(k["is_active"]),
                "issued_at": k["issued_at"]
            })

        return jsonify({"user_id": user_id, "key_history": results}), 200
    finally:
        conn.close()


# ------------------------------------------------------------------ #
# Phase 4: Epoch & Revocation Endpoints                              #
# ------------------------------------------------------------------ #

@admin_bp.route("/epoch", methods=["GET"])
@require_admin
def get_epoch_info():
    """
    Get current system epoch, lifecycle rotation state, document statistics, and epoch history.
    """
    crypto_svc = CryptoService.get_instance()
    info = crypto_svc.get_current_epoch_info()
    return jsonify(info), 200


@admin_bp.route("/epoch/advance", methods=["POST"])
@require_admin
def advance_epoch():
    """
    Stage 1: Advance the global system epoch with an administrative justification.
    Marks active users for key reissuance under the new epoch.
    """
    data = request.get_json() or {}
    reason = data.get("reason", "").strip()

    if not reason:
        return jsonify({"error": "ValidationFailed", "message": "Administrative justification reason is required."}), 400

    crypto_svc = CryptoService.get_instance()
    new_epoch = crypto_svc.advance_system_epoch(
        admin_id=g.current_user["id"],
        admin_username=g.current_user["username"],
        reason=reason,
        ip_address=request.remote_addr
    )

    return jsonify({
        "message": f"System epoch advanced to Epoch {new_epoch}.",
        "new_epoch": new_epoch,
        "reason": reason
    }), 200


@admin_bp.route("/epoch/reencrypt/<int:doc_id>", methods=["POST"])
@require_admin
def reencrypt_single_document(doc_id: int):
    """
    Stage 2: Re-encrypt an individual document under the current system epoch.
    Enforces CP-ABE policy authorization: the caller must provide their password,
    and their active private key must mathematically satisfy the document's access policy.
    """
    data = request.get_json() or {}
    password = data.get("password", "").strip()

    if not password:
        return jsonify({"error": "ValidationFailed", "message": "Password required to unlock authorized key for re-encryption."}), 400

    crypto_svc = CryptoService.get_instance()
    try:
        doc_info = crypto_svc.reencrypt_document(
            doc_id=doc_id,
            reencryptor_user_id=g.current_user["id"],
            reencryptor_username=g.current_user["username"],
            reencryptor_passphrase=password,
            ip_address=request.remote_addr
        )
        return jsonify({
            "message": f"Document #{doc_id} re-encrypted successfully under Epoch {doc_info['epoch']}.",
            "document": doc_info
        }), 200

    except AccessDeniedError as e:
        return jsonify({
            "error": "AccessDenied",
            "message": f"Administrator CP-ABE key is not authorized for document #{doc_id}: {str(e)}",
            "cryptographic_status": "DENIED"
        }), 403
    except ValueError as ve:
        return jsonify({"error": "AuthenticationFailed", "message": str(ve)}), 401
    except Exception as e:
        return jsonify({"error": "ReencryptionFailed", "message": str(e)}), 500


@admin_bp.route("/epoch/reencrypt-all", methods=["POST"])
@require_admin
def reencrypt_all_documents():
    """
    Stage 2 (Bulk): Re-encrypt all designated vault documents under the current system epoch.
    Enforces lifecycle state machine: reports PARTIAL_FAILURE if any document fails.
    """
    data = request.get_json() or {}
    password = data.get("password", "").strip()

    if not password:
        return jsonify({"error": "ValidationFailed", "message": "Password required to unlock authorized key for re-encryption."}), 400

    crypto_svc = CryptoService.get_instance()
    try:
        summary = crypto_svc.reencrypt_all_documents(
            reencryptor_user_id=g.current_user["id"],
            reencryptor_username=g.current_user["username"],
            reencryptor_passphrase=password,
            ip_address=request.remote_addr
        )
        return jsonify(summary), 200

    except AccessDeniedError as e:
        return jsonify({
            "error": "AccessDenied",
            "message": f"Caller's key cannot satisfy document policy: {str(e)}",
            "cryptographic_status": "DENIED"
        }), 403
    except ValueError as ve:
        return jsonify({"error": "AuthenticationFailed", "message": str(ve)}), 401
    except Exception as e:
        return jsonify({"error": "ReencryptionFailed", "message": str(e)}), 500


@admin_bp.route("/revocation/verify", methods=["POST"])
@require_admin
def verify_revocation():
    """
    Stage 4: Mathematical verification endpoint.
    Runs genuine Charm-Crypto BSW07 pairing tests to prove that:
      - Old key (prior epoch) fails mathematically against the re-encrypted document.
      - New key (current epoch) succeeds mathematically.
    Security guarantee: Zero key material or secret group elements are ever returned.
    """
    data = request.get_json() or {}
    doc_id = data.get("doc_id")
    test_user_id = data.get("test_user_id")
    test_user_password = data.get("test_user_password", "").strip()
    old_key_version = data.get("old_key_version")
    new_key_version = data.get("new_key_version")

    if not all([doc_id, test_user_id, test_user_password]):
        return jsonify({
            "error": "ValidationFailed",
            "message": "doc_id, test_user_id, and test_user_password are required."
        }), 400

    crypto_svc = CryptoService.get_instance()
    try:
        diagnostics = crypto_svc.verify_revocation_cryptography(
            doc_id=int(doc_id),
            test_user_id=int(test_user_id),
            test_user_passphrase=test_user_password,
            old_key_version=int(old_key_version) if old_key_version is not None and str(old_key_version).strip() != "" else None,
            new_key_version=int(new_key_version) if new_key_version is not None and str(new_key_version).strip() != "" else None
        )
        return jsonify(diagnostics), 200

    except ValueError as ve:
        return jsonify({"error": "NotFoundOrInvalid", "message": str(ve)}), 404
    except Exception as e:
        return jsonify({"error": "VerificationError", "message": str(e)}), 500
