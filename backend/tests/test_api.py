"""
test_api.py — SecureVault Phase 2 API Integration Tests
Uses Flask's built-in test client (no live server required).

Tests:
  1. Auth: register, login (success + wrong password), unauthenticated access
  2. Admin authorization: admin-only endpoints reject non-admin callers
  3. Document upload, list, get metadata
  4. Cryptographic decryption:
       Alice  (Engineer + Level-3)  → SUCCESS
       Charlie (Manager + Level-3)  → SUCCESS
       Bob    (Student  + Level-3)  → DENIED (403)
       David  (Engineer + Level-2)  → DENIED (403)
  5. Attribute change + key re-issue: David → Level-3 → now succeeds
  6. Audit log: entries appear after key operations

Run:
    python3 -m pytest tests/test_api.py -v   (from backend/ directory)
  or
    python3 tests/test_api.py
"""

import io
import json
import os
import sys
import unittest

# Ensure backend package root is on path
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# Use an isolated in-memory database for tests (override config before import)
os.environ.setdefault("FLASK_DEBUG", "false")

import config  # noqa: E402  (must come before app import)

# Point config to temp paths so tests don't clobber production data
import tempfile
_tmp_dir = tempfile.mkdtemp(prefix="securevault_test_")
config.DATABASE_PATH    = os.path.join(_tmp_dir, "test.db")
config.MASTER_KEY_PATH  = os.path.join(_tmp_dir, "master.enc")
config.PUBLIC_KEY_PATH  = os.path.join(_tmp_dir, "public_key.json")
config.ENCRYPTED_DIR    = os.path.join(_tmp_dir, "encrypted")
config.ENCRYPTED_DOCS_DIR = config.ENCRYPTED_DIR
config.KEYS_DIR         = _tmp_dir
os.makedirs(config.ENCRYPTED_DIR, exist_ok=True)

# Reset the CryptoService singleton so it re-initialises with the patched paths
from crypto import service as _svc_mod
_svc_mod.CryptoService._instance = None

from app import create_app, initialise_services  # noqa: E402

# ── Minimal valid PDF bytes (PDF-1.4 with one blank page) ─────────────────────
SAMPLE_PDF = (
    b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n"
    b"xref\n0 4\n0000000000 65535 f\r\n0000000009 00000 n\r\n"
    b"0000000058 00000 n\r\n0000000115 00000 n\r\n"
    b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF\n"
)

DEFAULT_POLICY = "(Role:Engineer OR Role:Manager) AND Clearance:Level-3"

USERS = {
    "admin":   {"password": "Admin@2026!",   "role": "Role:Engineer",  "clearance": "Clearance:Level-3", "sys": "admin"},
    "alice":   {"password": "Alice@2026!",   "role": "Role:Engineer",  "clearance": "Clearance:Level-3", "sys": "user"},
    "bob":     {"password": "Bob@2026!",     "role": "Role:Student",   "clearance": "Clearance:Level-3", "sys": "user"},
    "charlie": {"password": "Charlie@2026!", "role": "Role:Manager",   "clearance": "Clearance:Level-3", "sys": "user"},
    "david":   {"password": "David@2026!",   "role": "Role:Engineer",  "clearance": "Clearance:Level-2", "sys": "user"},
}


class SecureVaultAPITests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Create Flask test client and seed all test users once."""
        flask_app = create_app()
        flask_app.config["TESTING"] = True
        initialise_services(flask_app)
        cls.client = flask_app.test_client()
        cls.app = flask_app
        cls.tokens = {}
        cls.doc_id = None

        # Register all test users and store tokens
        for username, info in USERS.items():
            resp = cls.client.post(
                "/api/auth/register",
                json={
                    "username": username,
                    "password": info["password"],
                    "role_attr": info["role"],
                    "clearance_attr": info["clearance"],
                    "system_role": info["sys"],
                },
                # First account bootstraps the system; the admin enrols the rest.
                headers={"Authorization": f"Bearer {cls.tokens['admin']}"} if "admin" in cls.tokens else {},
            )
            assert resp.status_code == 201, (
                f"Failed to register '{username}': {resp.get_data(as_text=True)}"
            )
            data = resp.get_json()
            cls.tokens[username] = data["token"]
            print(f"[setup] Registered '{username}' — key attrs: {info['role']}, {info['clearance']}")

        # Upload one document as admin so decryption tests have a target
        resp = cls.client.post(
            "/api/documents/upload",
            data={
                "file": (io.BytesIO(SAMPLE_PDF), "confidential.pdf"),
                "access_policy": DEFAULT_POLICY,
            },
            content_type="multipart/form-data",
            headers={"Authorization": f"Bearer {cls.tokens['admin']}"},
        )
        assert resp.status_code == 201, f"Upload failed: {resp.get_data(as_text=True)}"
        cls.doc_id = resp.get_json()["document"]["id"]
        print(f"[setup] Uploaded document id={cls.doc_id}")

    # ─────────────────────────── AUTH TESTS ──────────────────────────────────

    def test_01_login_success(self):
        resp = self.client.post(
            "/api/auth/login",
            json={"username": "alice", "password": USERS["alice"]["password"]},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("token", data)
        self.assertEqual(data["user"]["username"], "alice")

    def test_02_login_wrong_password(self):
        resp = self.client.post(
            "/api/auth/login",
            json={"username": "alice", "password": "WRONG_PASSWORD"},
        )
        self.assertEqual(resp.status_code, 401)

    def test_03_unauthenticated_access_rejected(self):
        """Calling a protected endpoint without a token returns 401."""
        resp = self.client.get("/api/documents")
        self.assertEqual(resp.status_code, 401)

    def test_04_me_endpoint(self):
        resp = self.client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {self.tokens['alice']}"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["user"]["username"], "alice")

    # ─────────────────────────── ADMIN TESTS ─────────────────────────────────

    def test_05_admin_list_users(self):
        resp = self.client.get(
            "/api/admin/users",
            headers={"Authorization": f"Bearer {self.tokens['admin']}"},
        )
        self.assertEqual(resp.status_code, 200)
        users = resp.get_json()["users"]
        usernames = [u["username"] for u in users]
        for name in USERS:
            self.assertIn(name, usernames)

    def test_06_non_admin_cannot_list_users(self):
        resp = self.client.get(
            "/api/admin/users",
            headers={"Authorization": f"Bearer {self.tokens['alice']}"},
        )
        self.assertEqual(resp.status_code, 403)

    def test_07_non_admin_cannot_update_attributes(self):
        # Fetch alice's id first
        resp = self.client.get(
            "/api/admin/users",
            headers={"Authorization": f"Bearer {self.tokens['admin']}"},
        )
        users = {u["username"]: u["id"] for u in resp.get_json()["users"]}
        resp2 = self.client.put(
            f"/api/admin/users/{users['alice']}/attributes",
            json={"role_attr": "Role:Manager", "clearance_attr": "Clearance:Level-3",
                  "user_passphrase": USERS["alice"]["password"]},
            headers={"Authorization": f"Bearer {self.tokens['alice']}"},
        )
        self.assertEqual(resp2.status_code, 403)

    # ────────────────────────── DOCUMENT TESTS ───────────────────────────────

    def test_08_list_documents(self):
        resp = self.client.get(
            "/api/documents",
            headers={"Authorization": f"Bearer {self.tokens['alice']}"},
        )
        self.assertEqual(resp.status_code, 200)
        docs = resp.get_json()["documents"]
        self.assertGreaterEqual(len(docs), 1)

    def test_09_get_document_metadata(self):
        resp = self.client.get(
            f"/api/documents/{self.doc_id}",
            headers={"Authorization": f"Bearer {self.tokens['alice']}"},
        )
        self.assertEqual(resp.status_code, 200)
        doc = resp.get_json()["document"]
        self.assertEqual(doc["id"], self.doc_id)
        self.assertEqual(doc["access_policy"], DEFAULT_POLICY)

    # ─────────────────── CRYPTOGRAPHIC DECRYPTION TESTS ──────────────────────

    def _decrypt(self, username, password):
        """Helper: attempt decryption and return (status_code, json_body)."""
        resp = self.client.post(
            f"/api/documents/{self.doc_id}/decrypt?as_base64=true",
            json={"password": password},
            headers={"Authorization": f"Bearer {self.tokens[username]}"},
        )
        return resp.status_code, resp.get_json()

    def test_10_alice_engineer_level3_succeeds(self):
        """Alice: Role:Engineer + Clearance:Level-3 → CP-ABE MUST succeed."""
        status, body = self._decrypt("alice", USERS["alice"]["password"])
        self.assertEqual(status, 200, f"Alice should decrypt. Got: {body}")
        self.assertIn("content_base64", body)
        # Verify the decrypted content is a valid PDF
        import base64
        pdf_bytes = base64.b64decode(body["content_base64"])
        self.assertTrue(pdf_bytes.startswith(b"%PDF"), "Decrypted content is not a valid PDF")
        print(f"  [✓] Alice decrypted {body['file_size']} bytes — valid PDF confirmed")

    def test_11_charlie_manager_level3_succeeds(self):
        """Charlie: Role:Manager + Clearance:Level-3 → CP-ABE MUST succeed."""
        status, body = self._decrypt("charlie", USERS["charlie"]["password"])
        self.assertEqual(status, 200, f"Charlie should decrypt. Got: {body}")
        self.assertIn("content_base64", body)
        print(f"  [✓] Charlie decrypted {body['file_size']} bytes")

    def test_12_bob_student_level3_denied(self):
        """Bob: Role:Student + Clearance:Level-3 → CP-ABE MUST deny (not engineer/manager)."""
        status, body = self._decrypt("bob", USERS["bob"]["password"])
        self.assertEqual(status, 403, f"Bob should be denied. Got HTTP {status}: {body}")
        self.assertIn("cryptographic_status", body)
        self.assertEqual(body["cryptographic_status"], "DENIED")
        print(f"  [✓] Bob cryptographically denied: {body.get('message', '')[:80]}")

    def test_13_david_engineer_level2_denied(self):
        """David: Role:Engineer + Clearance:Level-2 → CP-ABE MUST deny (insufficient clearance)."""
        status, body = self._decrypt("david", USERS["david"]["password"])
        self.assertEqual(status, 403, f"David should be denied. Got HTTP {status}: {body}")
        self.assertIn("cryptographic_status", body)
        self.assertEqual(body["cryptographic_status"], "DENIED")
        print(f"  [✓] David cryptographically denied: {body.get('message', '')[:80]}")

    # ──────────── ATTRIBUTE CHANGE → KEY REISSUE → NEW DECRYPTION ───────────

    def test_14_david_attribute_upgrade_then_succeeds(self):
        """
        Admin promotes David from Clearance:Level-2 to Clearance:Level-3.
        A new CP-ABE key is issued. David re-logs in and decryption must now succeed.
        """
        # 1. Get David's user id
        resp = self.client.get(
            "/api/admin/users",
            headers={"Authorization": f"Bearer {self.tokens['admin']}"},
        )
        users = {u["username"]: u["id"] for u in resp.get_json()["users"]}
        david_id = users["david"]

        # 2. Admin updates David's clearance to Level-3
        resp = self.client.put(
            f"/api/admin/users/{david_id}/attributes",
            json={
                "role_attr": "Role:Engineer",
                "clearance_attr": "Clearance:Level-3",
                "user_passphrase": USERS["david"]["password"],
            },
            headers={"Authorization": f"Bearer {self.tokens['admin']}"},
        )
        self.assertEqual(resp.status_code, 200, f"Attribute update failed: {resp.get_data(as_text=True)}")
        key_info = resp.get_json()["key_info"]
        self.assertGreaterEqual(key_info["version"], 2)
        print(f"  [✓] Admin upgraded David → Clearance:Level-3, new key v{key_info['version']}")

        # 3. David logs in again to get a fresh token
        resp = self.client.post(
            "/api/auth/login",
            json={"username": "david", "password": USERS["david"]["password"]},
        )
        self.assertEqual(resp.status_code, 200)
        new_token = resp.get_json()["token"]

        # 4. David decrypts with his upgraded key — must now succeed
        resp = self.client.post(
            f"/api/documents/{self.doc_id}/decrypt?as_base64=true",
            json={"password": USERS["david"]["password"]},
            headers={"Authorization": f"Bearer {new_token}"},
        )
        self.assertEqual(resp.status_code, 200, f"David (upgraded) should succeed. Got: {resp.get_data(as_text=True)}")
        import base64
        pdf_bytes = base64.b64decode(resp.get_json()["content_base64"])
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        print(f"  [✓] David (now Level-3) successfully decrypted document")

    # ────────────────────────── AUDIT LOG TESTS ───────────────────────────────

    def test_15_audit_logs_accessible_to_admin(self):
        resp = self.client.get(
            "/api/audit/logs",
            headers={"Authorization": f"Bearer {self.tokens['admin']}"},
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        logs = body["logs"]
        self.assertGreater(len(logs), 0, "Audit log should have entries after earlier operations")
        actions = {log["action"] for log in logs}
        # Expect these actions from prior tests
        self.assertTrue(
            actions & {"AUTH_LOGIN", "KEY_ISSUANCE", "DOC_UPLOAD", "DECRYPT_SUCCESS", "DECRYPT_DENIED"},
            f"Expected audit actions not found. Got: {actions}"
        )
        print(f"  [✓] Audit log has {len(logs)} entries. Actions: {sorted(actions)}")

    def test_16_audit_logs_rejected_for_non_admin(self):
        resp = self.client.get(
            "/api/audit/logs",
            headers={"Authorization": f"Bearer {self.tokens['alice']}"},
        )
        self.assertEqual(resp.status_code, 403)

    def test_17_user_audit_log_accessible_to_self(self):
        """Alice can read her own audit log."""
        # Get alice's ID
        resp = self.client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {self.tokens['alice']}"},
        )
        alice_id = resp.get_json()["user"]["id"]

        resp2 = self.client.get(
            f"/api/audit/logs/user/{alice_id}",
            headers={"Authorization": f"Bearer {self.tokens['alice']}"},
        )
        self.assertEqual(resp2.status_code, 200)
        logs = resp2.get_json()["logs"]
        self.assertGreater(len(logs), 0)
        print(f"  [✓] Alice's personal audit log has {len(logs)} entries")

    def test_18_health_endpoint(self):
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "ok")


if __name__ == "__main__":
    # Run with explicit verbosity and ordered test execution
    loader = unittest.TestLoader()
    loader.sortTestMethodsUsing = None   # keep definition order
    suite = loader.loadTestsFromTestCase(SecureVaultAPITests)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
