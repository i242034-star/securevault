"""
audit_chain.py — Cryptographic HMAC-SHA256 Hash Chaining for Audit Logs.
Provides tamper-evident audit logging with transactionally safe sequential chaining,
canonical representation hashing, and full chain integrity verification.
"""
import hashlib
import hmac
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import config

# Genesis block reference hash: 64 hexadecimal zeros (256-bit zero vector)
GENESIS_HASH = "0" * 64


def canonical_record_bytes(
    sequence_number: int,
    timestamp: str,
    user_id: Optional[int],
    username: str,
    action: str,
    status: str,
    details: str,
    ip_address: str,
    previous_hash: str
) -> bytes:
    """
    Constructs a deterministic canonical JSON byte representation of an audit record.
    Keys are strictly sorted with no whitespace separators to guarantee consistent hashing.
    """
    canonical_dict = {
        "action": str(action),
        "details": str(details if details is not None else ""),
        "ip_address": str(ip_address if ip_address is not None else "127.0.0.1"),
        "previous_hash": str(previous_hash),
        "sequence_number": int(sequence_number),
        "status": str(status),
        "timestamp": str(timestamp),
        "user_id": int(user_id) if user_id is not None else None,
        "username": str(username),
    }
    return json.dumps(canonical_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')


def compute_record_hmac(canonical_bytes: bytes, secret_key: str) -> str:
    """
    Computes HMAC-SHA256 over canonical bytes using the dedicated audit secret.
    """
    if not secret_key:
        raise ValueError("Audit HMAC secret key is required and cannot be empty.")
    return hmac.new(secret_key.encode('utf-8'), canonical_bytes, hashlib.sha256).hexdigest()


def record_audit_event(
    conn: sqlite3.Connection,
    user_id: Optional[int],
    username: str,
    action: str,
    status: str,
    details: str = "",
    ip_address: str = "127.0.0.1",
    secret_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Inserts a new audit log record linked into the cryptographic HMAC-SHA256 hash chain.
    Uses serialized transaction (BEGIN IMMEDIATE) to guarantee thread and concurrency safety.
    """
    if secret_key is None:
        secret_key = config.AUDIT_HMAC_SECRET
    if not secret_key:
        raise ValueError("AUDIT_HMAC_SECRET must be configured.")

    # Save original isolation level and switch to autocommit so BEGIN IMMEDIATE can be explicitly issued
    orig_isolation = conn.isolation_level
    conn.isolation_level = None

    try:
        conn.execute("BEGIN IMMEDIATE")

        # Determine sequence number and previous hash from latest committed record
        row = conn.execute(
            "SELECT sequence_number, record_hash FROM audit_logs WHERE sequence_number IS NOT NULL ORDER BY sequence_number DESC LIMIT 1"
        ).fetchone()

        if row is None or row["sequence_number"] is None:
            sequence_number = 1
            previous_hash = GENESIS_HASH
        else:
            sequence_number = int(row["sequence_number"]) + 1
            previous_hash = str(row["record_hash"])

        timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        canonical_bytes = canonical_record_bytes(
            sequence_number=sequence_number,
            timestamp=timestamp_str,
            user_id=user_id,
            username=username,
            action=action,
            status=status,
            details=details,
            ip_address=ip_address,
            previous_hash=previous_hash
        )

        record_hash = compute_record_hmac(canonical_bytes, secret_key)

        cursor = conn.execute(
            """
            INSERT INTO audit_logs (
                sequence_number, user_id, username, action, status, details, ip_address, timestamp, previous_hash, record_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sequence_number, user_id, username, action, status, details, ip_address, timestamp_str, previous_hash, record_hash
            )
        )
        record_id = cursor.lastrowid
        conn.execute("COMMIT")

        return {
            "id": record_id,
            "sequence_number": sequence_number,
            "previous_hash": previous_hash,
            "record_hash": record_hash,
            "timestamp": timestamp_str
        }
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.isolation_level = orig_isolation


def verify_chain_integrity(conn: sqlite3.Connection, secret_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Verifies the complete audit log hash chain from Genesis to head:
    1. Validates strict sequence continuity (1, 2, 3, ... N with no gaps or duplicates).
    2. Validates that previous_hash matches preceding record_hash.
    3. Recomputes HMAC-SHA256 from canonical record bytes and compares against stored record_hash.
    Detects record modifications, unauthorized additions, deletions, and reordering.
    """
    if secret_key is None:
        secret_key = config.AUDIT_HMAC_SECRET
    if not secret_key:
        raise ValueError("Audit HMAC secret key is required for verification.")

    cursor = conn.execute(
        """
        SELECT id, sequence_number, user_id, username, action, status, details, ip_address, timestamp, previous_hash, record_hash
        FROM audit_logs
        ORDER BY sequence_number ASC, id ASC
        """
    )
    rows = cursor.fetchall()

    if not rows:
        return {
            "valid": True,
            "total_records": 0,
            "verified_records": 0,
            "tampered": False,
            "errors": [],
            "genesis_hash": GENESIS_HASH,
            "latest_hash": None,
        }

    errors: List[str] = []
    expected_seq = 1
    expected_previous_hash = GENESIS_HASH

    for row in rows:
        seq = row["sequence_number"]
        rec_id = row["id"]

        # 1. Verify sequence continuity
        if seq is None:
            errors.append(f"Record id={rec_id} has NULL sequence_number (unmigrated or corrupted).")
            continue

        if seq != expected_seq:
            errors.append(
                f"Sequence discontinuity at record id={rec_id}: expected sequence {expected_seq}, found {seq}."
            )

        # 2. Verify previous hash link
        if row["previous_hash"] != expected_previous_hash:
            errors.append(
                f"Broken hash chain at sequence {seq} (id={rec_id}): stored previous_hash '{row['previous_hash']}' does not match expected preceding record hash '{expected_previous_hash}'."
            )

        # 3. Verify HMAC-SHA256 integrity
        canon_bytes = canonical_record_bytes(
            sequence_number=seq,
            timestamp=row["timestamp"],
            user_id=row["user_id"],
            username=row["username"],
            action=row["action"],
            status=row["status"],
            details=row["details"],
            ip_address=row["ip_address"],
            previous_hash=row["previous_hash"]
        )

        computed_hmac = compute_record_hmac(canon_bytes, secret_key)
        if not hmac.compare_digest(str(row["record_hash"]), computed_hmac):
            errors.append(
                f"Tampered record at sequence {seq} (id={rec_id}): stored record_hash does not match recomputed HMAC-SHA256."
            )

        expected_previous_hash = row["record_hash"]
        expected_seq = seq + 1

    return {
        "valid": len(errors) == 0,
        "total_records": len(rows),
        "verified_records": len(rows) - len(errors),
        "tampered": len(errors) > 0,
        "errors": errors,
        "genesis_hash": GENESIS_HASH,
        "latest_hash": rows[-1]["record_hash"] if rows else None,
    }


def migrate_legacy_records(conn: sqlite3.Connection, secret_key: Optional[str] = None) -> int:
    """
    Backfills existing audit_log rows lacking sequence_number or record_hash into the HMAC hash chain.
    Preserves original timestamps and ordering.
    
    SECURITY NOTE ON HISTORICAL RECORDS:
    Historical records backfilled during migration cannot mathematically prove they were never
    modified prior to the initialization of the hash chain; however, once migrated, any
    subsequent tampering or modification will be strictly detected.
    """
    if secret_key is None:
        secret_key = config.AUDIT_HMAC_SECRET

    legacy_rows = conn.execute(
        "SELECT id, user_id, username, action, status, details, ip_address, timestamp FROM audit_logs WHERE sequence_number IS NULL OR record_hash IS NULL ORDER BY id ASC"
    ).fetchall()

    if not legacy_rows:
        return 0

    # Determine starting sequence and previous hash
    last_row = conn.execute(
        "SELECT sequence_number, record_hash FROM audit_logs WHERE sequence_number IS NOT NULL ORDER BY sequence_number DESC LIMIT 1"
    ).fetchone()

    if last_row and last_row["sequence_number"] is not None:
        cur_seq = int(last_row["sequence_number"])
        cur_prev = str(last_row["record_hash"])
    else:
        cur_seq = 0
        cur_prev = GENESIS_HASH

    for row in legacy_rows:
        cur_seq += 1
        canon_bytes = canonical_record_bytes(
            sequence_number=cur_seq,
            timestamp=row["timestamp"] or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            user_id=row["user_id"],
            username=row["username"],
            action=row["action"],
            status=row["status"],
            details=row["details"] or "",
            ip_address=row["ip_address"] or "127.0.0.1",
            previous_hash=cur_prev
        )
        rec_hash = compute_record_hmac(canon_bytes, secret_key)
        conn.execute(
            "UPDATE audit_logs SET sequence_number = ?, previous_hash = ?, record_hash = ? WHERE id = ?",
            (cur_seq, cur_prev, rec_hash, row["id"])
        )
        cur_prev = rec_hash

    conn.commit()
    return len(legacy_rows)
