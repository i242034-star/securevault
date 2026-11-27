"""
audit_routes.py — Audit log endpoints (admin-only)
Blueprint prefix: /api/audit
"""

from flask import Blueprint, jsonify, request, g
from models.database import get_db
from utils.auth import require_admin, require_auth

audit_bp = Blueprint("audit", __name__)


@audit_bp.route("/logs", methods=["GET"])
@require_admin
def get_audit_logs():
    """
    GET /api/audit/logs
    Returns paginated audit log entries (admin only).
    Query params: page (default 1), per_page (default 50), action, status, username
    """
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(200, max(1, int(request.args.get("per_page", 50))))
    filter_action = request.args.get("action", "").strip()
    filter_status = request.args.get("status", "").strip()
    filter_username = request.args.get("username", "").strip()

    db = get_db()

    # Build dynamic WHERE clause
    conditions = []
    params = []

    if filter_action:
        conditions.append("action = ?")
        params.append(filter_action)
    if filter_status:
        conditions.append("status = ?")
        params.append(filter_status)
    if filter_username:
        conditions.append("username LIKE ?")
        params.append(f"%{filter_username}%")

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    # Count total
    count_row = db.execute(
        f"SELECT COUNT(*) FROM audit_logs {where_clause}", params
    ).fetchone()
    total = count_row[0]

    # Fetch page
    offset = (page - 1) * per_page
    rows = db.execute(
        f"""
        SELECT id, sequence_number, user_id, username, action, status, details, ip_address, timestamp, previous_hash, record_hash
        FROM audit_logs
        {where_clause}
        ORDER BY sequence_number DESC, id DESC
        LIMIT ? OFFSET ?
        """,
        params + [per_page, offset],
    ).fetchall()

    logs = [
        {
            "id": r["id"],
            "sequence_number": r["sequence_number"],
            "user_id": r["user_id"],
            "username": r["username"],
            "action": r["action"],
            "status": r["status"],
            "details": r["details"],
            "ip_address": r["ip_address"],
            "timestamp": r["timestamp"],
            "previous_hash": r["previous_hash"],
            "record_hash": r["record_hash"],
        }
        for r in rows
    ]

    return jsonify(
        {
            "logs": logs,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "pages": max(1, (total + per_page - 1) // per_page),
            },
        }
    )


@audit_bp.route("/logs/user/<int:user_id>", methods=["GET"])
@require_auth
def get_user_audit_logs(user_id):
    """
    GET /api/audit/logs/user/<id>
    Returns audit logs for a specific user.
    Admin may query any user; regular users may only query themselves.
    """
    if g.current_user["system_role"] != "admin" and g.current_user["id"] != user_id:
        return jsonify({"error": "Forbidden: cannot view another user's audit logs"}), 403

    page = max(1, int(request.args.get("page", 1)))
    per_page = min(100, max(1, int(request.args.get("per_page", 25))))
    offset = (page - 1) * per_page

    db = get_db()

    total = db.execute(
        "SELECT COUNT(*) FROM audit_logs WHERE user_id = ?", (user_id,)
    ).fetchone()[0]

    rows = db.execute(
        """
        SELECT id, sequence_number, user_id, username, action, status, details, ip_address, timestamp, previous_hash, record_hash
        FROM audit_logs
        WHERE user_id = ?
        ORDER BY sequence_number DESC, id DESC
        LIMIT ? OFFSET ?
        """,
        (user_id, per_page, offset),
    ).fetchall()

    logs = [
        {
            "id": r["id"],
            "sequence_number": r["sequence_number"],
            "user_id": r["user_id"],
            "username": r["username"],
            "action": r["action"],
            "status": r["status"],
            "details": r["details"],
            "ip_address": r["ip_address"],
            "timestamp": r["timestamp"],
            "previous_hash": r["previous_hash"],
            "record_hash": r["record_hash"],
        }
        for r in rows
    ]

    return jsonify(
        {
            "user_id": user_id,
            "logs": logs,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "pages": max(1, (total + per_page - 1) // per_page),
            },
        }
    )


@audit_bp.route("/logs/actions", methods=["GET"])
@require_admin
def get_distinct_actions():
    """
    GET /api/audit/logs/actions
    Returns the distinct set of action types in the audit log.
    Useful for the frontend filter dropdown.
    """
    db = get_db()
    rows = db.execute(
        "SELECT DISTINCT action FROM audit_logs ORDER BY action"
    ).fetchall()
    return jsonify({"actions": [r["action"] for r in rows]})


@audit_bp.route("/verify", methods=["GET"])
@require_admin
def verify_audit_log_chain():
    """
    GET /api/audit/verify
    Admin-only endpoint: cryptographically verifies the HMAC-SHA256 hash-chain integrity
    of all audit logs. Returns 200 if valid, 409 if any tampering or broken link is detected.
    """
    db = get_db()
    try:
        from crypto.audit_chain import verify_chain_integrity
        result = verify_chain_integrity(db)
        status_code = 200 if result["valid"] else 409
        return jsonify(result), status_code
    finally:
        db.close()
