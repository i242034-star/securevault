"""
Document Routes: Upload, Listing, Encrypted Download, and Authorized Decryption
"""
from flask import Blueprint, request, jsonify, g, send_file, Response
import base64
import io
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import config
from models.database import get_db
from utils.auth import require_auth
from crypto.service import CryptoService
from crypto.hybrid_cipher import AccessDeniedError, TamperError

document_bp = Blueprint("documents", __name__)


@document_bp.route("/upload", methods=["POST"])
@require_auth
def upload_document():
    """
    Upload a document (e.g. confidential PDF) and encrypt it using hybrid encryption:
    - PDF encrypted using AES-256-GCM
    - AES key encapsulated under specified policy using genuine BSW07 CP-ABE
    """
    if "file" not in request.files:
        return jsonify({"error": "ValidationFailed", "message": "No file uploaded in 'file' field."}), 400

    uploaded_file = request.files["file"]
    if not uploaded_file or uploaded_file.filename == "":
        return jsonify({"error": "ValidationFailed", "message": "Uploaded file is empty or missing filename."}), 400

    policy_str = request.form.get("access_policy", config.DEFAULT_CORE_POLICY).strip()
    if not policy_str:
        policy_str = config.DEFAULT_CORE_POLICY

    attach_epoch = request.form.get("attach_epoch", "false").lower() == "true"

    file_bytes = uploaded_file.read()
    if len(file_bytes) == 0:
        return jsonify({"error": "ValidationFailed", "message": "File cannot be 0 bytes."}), 400

    crypto_svc = CryptoService.get_instance()
    try:
        doc_info = crypto_svc.encrypt_and_store_document(
            uploader_id=g.current_user["id"],
            uploader_username=g.current_user["username"],
            original_filename=uploaded_file.filename,
            file_bytes=file_bytes,
            policy_str=policy_str,
            ip_address=request.remote_addr,
            attach_epoch=attach_epoch
        )

        return jsonify({
            "message": "Document encrypted and stored securely.",
            "document": doc_info
        }), 201

    except Exception as e:
        return jsonify({"error": "EncryptionFailed", "message": f"Cryptographic encryption error: {str(e)}"}), 500


@document_bp.route("", methods=["GET"])
@require_auth
def list_documents():
    """
    List all encrypted documents in the locker with their access policies, epoch, and encryption metadata.
    """
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT d.id, d.original_filename, d.file_size, d.access_policy, d.formatted_policy,
                   d.epoch, d.created_at, u.username AS uploader_username
            FROM documents d
            JOIN users u ON d.uploader_id = u.id
            ORDER BY d.id DESC
        """).fetchall()

        results = [dict(r) for r in rows]
        return jsonify({"documents": results}), 200
    finally:
        conn.close()


@document_bp.route("/<int:doc_id>", methods=["GET"])
@require_auth
def get_document(doc_id: int):
    """
    Get metadata for a specific encrypted document.
    """
    conn = get_db()
    try:
        row = conn.execute("""
            SELECT d.id, d.original_filename, d.file_size, d.access_policy, d.formatted_policy,
                   d.epoch, d.created_at, u.username AS uploader_username
            FROM documents d
            JOIN users u ON d.uploader_id = u.id
            WHERE d.id = ?
        """, (doc_id,)).fetchone()

        if not row:
            return jsonify({"error": "NotFound", "message": f"Document #{doc_id} not found."}), 404

        return jsonify({"document": dict(row)}), 200
    finally:
        conn.close()


@document_bp.route("/<int:doc_id>/download-encrypted", methods=["GET"])
@require_auth
def download_encrypted_blob(doc_id: int):
    """
    Download raw AES ciphertext blob from disk for security inspection or offline cryptographic proof.
    """
    conn = get_db()
    try:
        doc = conn.execute("SELECT stored_filename, original_filename FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not doc:
            return jsonify({"error": "NotFound", "message": f"Document #{doc_id} not found."}), 404

        disk_path = os.path.join(config.ENCRYPTED_DIR, doc["stored_filename"])
        if not os.path.exists(disk_path):
            return jsonify({"error": "NotFound", "message": "Encrypted file missing from storage."}), 404

        return send_file(
            disk_path,
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=f"{doc['original_filename']}.enc"
        )
    finally:
        conn.close()


@document_bp.route("/<int:doc_id>/decrypt", methods=["POST"])
@require_auth
def decrypt_document_endpoint(doc_id: int):
    """
    Authorized Decryption Endpoint:
    1. Authenticated user provides their password to unlock their private key in transient memory.
    2. Backend performs genuine CP-ABE decryption to recover the AES key.
    3. Backend decrypts and verifies the PDF using AES-256-GCM.
    4. If attributes do not satisfy policy, returns HTTP 403 Forbidden with cryptographic denial details.
    """
    data = request.get_json() or {}
    password = data.get("password", "").strip()

    if not password:
        return jsonify({"error": "ValidationFailed", "message": "User password is required to unlock your private key."}), 400

    crypto_svc = CryptoService.get_instance()
    try:
        decrypted_bytes, filename = crypto_svc.decrypt_document(
            user_id=g.current_user["id"],
            username=g.current_user["username"],
            doc_id=doc_id,
            user_passphrase=password,
            ip_address=request.remote_addr
        )

        as_base64 = request.args.get("as_base64", "false").lower() == "true"
        if as_base64:
            b64_content = base64.b64encode(decrypted_bytes).decode('ascii')
            return jsonify({
                "message": "Document decrypted successfully.",
                "filename": filename,
                "file_size": len(decrypted_bytes),
                "content_base64": b64_content
            }), 200

        # Return as PDF file stream
        return send_file(
            io.BytesIO(decrypted_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename
        )

    except AccessDeniedError as e:
        return jsonify({
            "error": "AccessDenied",
            "message": str(e),
            "cryptographic_status": "DENIED",
            "user_attributes": [g.current_user["role_attr"], g.current_user["clearance_attr"]]
        }), 403

    except TamperError as e:
        return jsonify({
            "error": "TamperDetected",
            "message": str(e),
            "cryptographic_status": "INTEGRITY_FAILURE"
        }), 422

    except ValueError as e:
        return jsonify({
            "error": "AuthenticationFailed",
            "message": str(e)
        }), 401

    except Exception as e:
        return jsonify({
            "error": "DecryptionFailed",
            "message": f"Decryption error: {str(e)}"
        }), 500
