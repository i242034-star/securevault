"""
test_audit_chain_and_cors.py — Security Hardening Verification Suite
Tests:
1. CORS configuration: allowed origin accepted, untrusted origin rejected, preflight options.
2. Tamper-evident audit logging:
   - Normal sequential insertion
   - Valid chain verification
   - Detection of record modification
   - Detection of previous_hash alteration
   - Detection of record reordering
   - Detection of record deletion
   - Invalid or missing HMAC secret handling
   - Admin-only access to verification endpoint
   - High-concurrency audit event writing (thread safety)
   - Zero leakage of passwords, tokens, keys, and HMAC secret
   - Legacy unchained record migration
"""
import concurrent.futures
import json
import os
import sqlite3
import sys
import tempfile
import unittest

# Ensure backend root is on sys.path
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# Isolated test environment setup
os.environ["FLASK_DEBUG"] = "false"
os.environ["AUDIT_HMAC_SECRET"] = "Test_Audit_HMAC_Secret_Key_98765!"
import config

_tmp_dir = tempfile.mkdtemp(prefix="securevault_hardening_test_")
config.DATABASE_PATH = os.path.join(_tmp_dir, "test_hardening.db")
config.MASTER_KEY_PATH = os.path.join(_tmp_dir, "master.enc")
config.PUBLIC_KEY_PATH = os.path.join(_tmp_dir, "public_key.json")
config.ENCRYPTED_DIR = os.path.join(_tmp_dir, "encrypted")
config.ENCRYPTED_DOCS_DIR = config.ENCRYPTED_DIR
config.KEYS_DIR = _tmp_dir
os.makedirs(config.ENCRYPTED_DIR, exist_ok=True)

# Reset CryptoService singleton
from crypto import service as _svc_mod
_svc_mod.CryptoService._instance = None

from app import create_app, initialise_services
from crypto.audit_chain import (
    GENESIS_HASH,
    canonical_record_bytes,
    compute_record_hmac,
    record_audit_event,
    verify_chain_integrity,
    migrate_legacy_records,
)
from models.database import get_db, init_db


class TestAuditChainAndCORS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        initialise_services(cls.app)
        cls.client = cls.app.test_client()

        # Create admin and regular user for endpoint testing
        conn = get_db()
        from utils.auth import hash_password, generate_token
        conn.execute(
            "INSERT INTO users (username, password_hash, system_role, role_attr, clearance_attr) VALUES (?, ?, ?, ?, ?)",
            ("admin_user", hash_password("AdminPass123!"), "admin", "Role:Manager", "Clearance:Level-3")
        )
        admin_id = conn.execute("SELECT id FROM users WHERE username = 'admin_user'").fetchone()[0]

        conn.execute(
            "INSERT INTO users (username, password_hash, system_role, role_attr, clearance_attr) VALUES (?, ?, ?, ?, ?)",
            ("regular_user", hash_password("UserPass123!"), "user", "Role:Engineer", "Clearance:Level-3")
        )
        user_id = conn.execute("SELECT id FROM users WHERE username = 'regular_user'").fetchone()[0]
        conn.commit()
        conn.close()

        cls.admin_token = generate_token(admin_id, "admin_user", "admin")
        cls.user_token = generate_token(user_id, "regular_user", "user")

    # ──────────────────────────── 1. CORS TESTS ───────────────────────────── #

    def test_cors_configured_origin_accepted(self):
        """Configured frontend origin (e.g. http://localhost:5173) must receive CORS headers."""
        resp = self.client.get(
            "/api/health",
            headers={"Origin": "http://localhost:5173"}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("Access-Control-Allow-Origin"), "http://localhost:5173")
        self.assertEqual(resp.headers.get("Access-Control-Allow-Credentials"), "true")

    def test_cors_untrusted_origin_rejected(self):
        """Untrusted origin must NOT receive Access-Control-Allow-Origin."""
        resp = self.client.get(
            "/api/health",
            headers={"Origin": "http://evil-attacker.example.com"}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(resp.headers.get("Access-Control-Allow-Origin"))

    def test_cors_preflight_options(self):
        """Preflight OPTIONS request from trusted origin succeeds with allow methods."""
        resp = self.client.options(
            "/api/auth/login",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type,Authorization"
            }
        )
        self.assertIn(resp.status_code, [200, 204])
        self.assertEqual(resp.headers.get("Access-Control-Allow-Origin"), "http://localhost:5173")

        # Untrusted preflight
        resp2 = self.client.options(
            "/api/auth/login",
            headers={
                "Origin": "http://untrusted-site.org",
                "Access-Control-Request-Method": "POST"
            }
        )
        self.assertIsNone(resp2.headers.get("Access-Control-Allow-Origin"))

    # ─────────────────────── 2. AUDIT CHAIN CORE TESTS ────────────────────── #

    def test_normal_audit_event_insertion_and_chain(self):
        """Insert events and verify sequential chaining, previous_hash links, and HMACs."""
        conn = get_db()
        # Clean audit_logs for isolated test
        conn.execute("DELETE FROM audit_logs")
        conn.commit()

        # Insert 3 events
        ev1 = record_audit_event(conn, 1, "alice", "AUTH_LOGIN", "SUCCESS", "User logged in", "192.168.1.10")
        ev2 = record_audit_event(conn, 1, "alice", "DOC_UPLOAD", "SUCCESS", "Uploaded report.pdf", "192.168.1.10")
        ev3 = record_audit_event(conn, 2, "bob", "DECRYPT_DENIED", "DENIED", "Access denied", "192.168.1.20")

        self.assertEqual(ev1["sequence_number"], 1)
        self.assertEqual(ev1["previous_hash"], GENESIS_HASH)

        self.assertEqual(ev2["sequence_number"], 2)
        self.assertEqual(ev2["previous_hash"], ev1["record_hash"])

        self.assertEqual(ev3["sequence_number"], 3)
        self.assertEqual(ev3["previous_hash"], ev2["record_hash"])

        # Check in DB
        rows = conn.execute("SELECT * FROM audit_logs ORDER BY sequence_number ASC").fetchall()
        self.assertEqual(len(rows), 3)
        conn.close()

    def test_valid_chain_verification(self):
        """Intact audit log chain verifies with 100% validity and 0 errors."""
        conn = get_db()
        result = verify_chain_integrity(conn)
        conn.close()

        self.assertTrue(result["valid"])
        self.assertFalse(result["tampered"])
        self.assertEqual(result["total_records"], 3)
        self.assertEqual(result["verified_records"], 3)
        self.assertEqual(len(result["errors"]), 0)

    def test_tampering_record_modification_detected(self):
        """Modifying the details of an existing record must trigger an HMAC verification error."""
        conn = get_db()
        # Tamper with record #2 details directly in DB
        conn.execute("UPDATE audit_logs SET details = 'HACKED: Document was deleted' WHERE sequence_number = 2")
        conn.commit()

        result = verify_chain_integrity(conn)
        self.assertFalse(result["valid"])
        self.assertTrue(result["tampered"])
        self.assertTrue(any("stored record_hash does not match" in e for e in result["errors"]))

        # Restore original details
        conn.execute("UPDATE audit_logs SET details = 'Uploaded report.pdf' WHERE sequence_number = 2")
        conn.commit()

        # Verify chain is restored
        restored_result = verify_chain_integrity(conn)
        self.assertTrue(restored_result["valid"])
        conn.close()

    def test_tampering_previous_hash_modification_detected(self):
        """Altering previous_hash must break the cryptographic link."""
        conn = get_db()
        fake_hash = "f" * 64
        conn.execute("UPDATE audit_logs SET previous_hash = ? WHERE sequence_number = 2", (fake_hash,))
        conn.commit()

        result = verify_chain_integrity(conn)
        self.assertFalse(result["valid"])
        self.assertTrue(result["tampered"])
        self.assertTrue(any("does not match expected preceding record hash" in e for e in result["errors"]))

        # Revert
        prev_hash = conn.execute("SELECT record_hash FROM audit_logs WHERE sequence_number = 1").fetchone()[0]
        conn.execute("UPDATE audit_logs SET previous_hash = ? WHERE sequence_number = 2", (prev_hash,))
        conn.commit()
        conn.close()

    def test_tampering_record_reordering_detected(self):
        """Swapping sequence numbers of two records must be detected as sequence discontinuity and HMAC mismatch."""
        conn = get_db()
        # Swap sequence_number of record 1 and 2
        conn.execute("UPDATE audit_logs SET sequence_number = 999 WHERE sequence_number = 1")
        conn.execute("UPDATE audit_logs SET sequence_number = 1 WHERE sequence_number = 2")
        conn.execute("UPDATE audit_logs SET sequence_number = 2 WHERE sequence_number = 999")
        conn.commit()

        result = verify_chain_integrity(conn)
        self.assertFalse(result["valid"])
        self.assertTrue(result["tampered"])

        # Revert
        conn.execute("UPDATE audit_logs SET sequence_number = 999 WHERE sequence_number = 1")
        conn.execute("UPDATE audit_logs SET sequence_number = 1 WHERE sequence_number = 2")
        conn.execute("UPDATE audit_logs SET sequence_number = 2 WHERE sequence_number = 999")
        conn.commit()
        conn.close()

    def test_tampering_record_deletion_detected(self):
        """Deleting a record from the middle of the chain must break sequence continuity and hash linkage."""
        conn = get_db()
        # Save record 2 before deletion
        row2 = dict(conn.execute("SELECT * FROM audit_logs WHERE sequence_number = 2").fetchone())

        conn.execute("DELETE FROM audit_logs WHERE sequence_number = 2")
        conn.commit()

        result = verify_chain_integrity(conn)
        self.assertFalse(result["valid"])
        self.assertTrue(result["tampered"])
        # Should detect sequence discontinuity (seq 3 encountered after seq 1)
        self.assertTrue(any("Sequence discontinuity" in e for e in result["errors"]))

        # Re-insert row2 to restore chain
        conn.execute(
            """
            INSERT INTO audit_logs (id, sequence_number, user_id, username, action, status, details, ip_address, timestamp, previous_hash, record_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (row2["id"], row2["sequence_number"], row2["user_id"], row2["username"], row2["action"], row2["status"], row2["details"], row2["ip_address"], row2["timestamp"], row2["previous_hash"], row2["record_hash"])
        )
        conn.commit()
        self.assertTrue(verify_chain_integrity(conn)["valid"])
        conn.close()

    def test_invalid_or_missing_hmac_secret(self):
        """Missing secret key raises ValueError; mismatched secret fails verification."""
        conn = get_db()
        count = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]

        # Empty secret
        with self.assertRaises(ValueError):
            verify_chain_integrity(conn, secret_key="")

        # Wrong secret key
        wrong_result = verify_chain_integrity(conn, secret_key="Completely_Wrong_HMAC_Secret_Key!")
        self.assertFalse(wrong_result["valid"])
        self.assertTrue(wrong_result["tampered"])
        # All records should fail HMAC check
        self.assertEqual(len(wrong_result["errors"]), count)
        conn.close()

    # ─────────────────── 3. ENDPOINT AUTHORIZATION TESTS ──────────────────── #

    def test_verification_endpoint_admin_only(self):
        """Endpoint /api/audit/verify: Admin gets 200; regular user gets 403; unauthenticated gets 401."""
        # Unauthenticated
        resp_unauth = self.client.get("/api/audit/verify")
        self.assertEqual(resp_unauth.status_code, 401)

        # Regular user (non-admin)
        resp_user = self.client.get(
            "/api/audit/verify",
            headers={"Authorization": f"Bearer {self.user_token}"}
        )
        self.assertEqual(resp_user.status_code, 403)

        # Admin user
        resp_admin = self.client.get(
            "/api/audit/verify",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp_admin.status_code, 200)
        data = resp_admin.get_json()
        self.assertTrue(data["valid"])
        self.assertFalse(data["tampered"])
        self.assertGreater(data["total_records"], 0)

    # ────────────────── 4. CONCURRENT AUDIT WRITES TEST ───────────────────── #

    def test_concurrent_audit_writes(self):
        """Multiple threads concurrently writing audit events must be serialized safely without corruption."""
        NUM_THREADS = 15

        conn = get_db()
        initial_count = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
        conn.close()

        def worker_log(thread_idx):
            from crypto.service import CryptoService
            svc = CryptoService.get_instance()
            svc.log_audit(
                user_id=1,
                username=f"worker_{thread_idx}",
                action="CONCURRENT_TEST",
                status="SUCCESS",
                details=f"Concurrent write from thread #{thread_idx}"
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
            futures = [executor.submit(worker_log, i) for i in range(NUM_THREADS)]
            concurrent.futures.wait(futures)
            for f in futures:
                f.result()  # Raise if any worker failed

        conn = get_db()
        result = verify_chain_integrity(conn)
        conn.close()

        self.assertTrue(result["valid"], f"Concurrent writes corrupted chain: {result['errors']}")
        self.assertFalse(result["tampered"])
        self.assertEqual(result["total_records"], initial_count + NUM_THREADS)

    # ────────────────── 5. ZERO SENSITIVE LEAKAGE TEST ────────────────────── #

    def test_zero_sensitive_data_in_audit_records(self):
        """Audit log records must never contain passwords, JWT tokens, private keys, or HMAC secrets."""
        conn = get_db()
        rows = conn.execute("SELECT * FROM audit_logs").fetchall()
        conn.close()

        forbidden_strings = [
            "AdminPass123!",
            "UserPass123!",
            "Test_Audit_HMAC_Secret_Key_98765!",
            config.AUDIT_HMAC_SECRET,
            "Bearer ",
            "cpabe_sk",
            "bsw07_sk",
        ]

        for r in rows:
            for col in ["details", "action", "username", "status", "ip_address"]:
                val = str(r[col] or "")
                for forbidden in forbidden_strings:
                    self.assertNotIn(
                        forbidden, val,
                        f"Sensitive leak detected in audit row id={r['id']}, col={col}: found '{forbidden}'"
                    )

    # ────────────────── 6. LEGACY MIGRATION TEST ─────────────────────────── #

    def test_legacy_record_migration(self):
        """Unchained legacy rows are backfilled with sequence numbers and chained HMACs."""
        conn = get_db()
        # Insert a simulated legacy unchained row
        conn.execute(
            "INSERT INTO audit_logs (username, action, status, details, ip_address) VALUES ('legacy_user', 'LEGACY_ACTION', 'SUCCESS', 'Pre-chain legacy event', '10.0.0.1')"
        )
        conn.commit()

        # Check it has NULL sequence_number and record_hash
        legacy_row = conn.execute("SELECT * FROM audit_logs WHERE username = 'legacy_user'").fetchone()
        self.assertIsNone(legacy_row["sequence_number"])
        self.assertIsNone(legacy_row["record_hash"])

        # Run migration
        migrated_count = migrate_legacy_records(conn)
        self.assertGreaterEqual(migrated_count, 1)

        # Verify chain integrity now includes the legacy record
        result = verify_chain_integrity(conn)
        self.assertTrue(result["valid"], f"Migration broke chain: {result['errors']}")

        # Verify legacy row now has sequence_number and record_hash
        migrated_row = conn.execute("SELECT * FROM audit_logs WHERE username = 'legacy_user'").fetchone()
        self.assertIsNotNone(migrated_row["sequence_number"])
        self.assertIsNotNone(migrated_row["record_hash"])
        self.assertIsNotNone(migrated_row["previous_hash"])
        conn.close()


if __name__ == "__main__":
    loader = unittest.TestLoader()
    loader.sortTestMethodsUsing = None
    suite = loader.loadTestsFromTestCase(TestAuditChainAndCORS)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
