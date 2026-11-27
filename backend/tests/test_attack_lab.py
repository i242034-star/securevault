"""
test_attack_lab.py — Simulated attacks & countermeasures

  1. Every Attack Lab simulation runs real crypto and reports BLOCKED.
  2. Login rate limiter locks after 5 failures, per (username, IP).
  3. Registration is admin-only after bootstrap; self-escalation is refused.
  4. /api/auth/login returns 429 during lockout; /api/attacks endpoints work.

Run:  python3 -m unittest tests.test_attack_lab -v   (from backend/)
"""
import os
import sys
import tempfile
import unittest

BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

import config  # noqa: E402

_tmp_dir = tempfile.mkdtemp(prefix="securevault_attack_test_")
config.DATABASE_PATH = os.path.join(_tmp_dir, "test.db")
config.MASTER_KEY_PATH = os.path.join(_tmp_dir, "master.enc")
config.PUBLIC_KEY_PATH = os.path.join(_tmp_dir, "public_key.json")
config.ENCRYPTED_DIR = os.path.join(_tmp_dir, "encrypted")
config.ENCRYPTED_DOCS_DIR = config.ENCRYPTED_DIR
config.KEYS_DIR = _tmp_dir
os.makedirs(config.ENCRYPTED_DIR, exist_ok=True)

from crypto import service as _svc_mod  # noqa: E402
_svc_mod.CryptoService._instance = None

from app import create_app, initialise_services  # noqa: E402
from crypto.attack_simulator import AttackSimulator, ATTACK_CATALOG  # noqa: E402
from utils.rate_limit import LoginRateLimiter, login_limiter  # noqa: E402


class TestAttackSimulations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sim = AttackSimulator()

    def _assert_blocked(self, result):
        self.assertEqual(result["outcome"], "BLOCKED", result)
        for field in ("id", "name", "steps", "countermeasure", "evidence", "duration_ms"):
            self.assertIn(field, result)

    def test_collusion_blocked(self):
        r = self.sim.collusion()
        self._assert_blocked(r)
        self.assertEqual(r["evidence"]["bob_alone"], "POLICY_UNSATISFIED")
        self.assertEqual(r["evidence"]["david_alone"], "POLICY_UNSATISFIED")
        # Labels satisfy the policy, so the failure must come from the pairing math
        self.assertEqual(r["evidence"]["merged_key"], "PAIRING_MISMATCH")

    def test_policy_tampering_blocked(self):
        r = self.sim.policy_tampering()
        self._assert_blocked(r)
        self.assertFalse(r["evidence"]["session_secret_recovered"])

    def test_ciphertext_tamper_detected(self):
        r = self.sim.ciphertext_tamper()
        self._assert_blocked(r)
        self.assertTrue(r["evidence"]["baseline_decrypt_ok"])
        self.assertTrue(all(t["detected"] for t in r["evidence"]["trials"]))

    def test_revoked_key_denied(self):
        r = self.sim.revoked_key()
        self._assert_blocked(r)
        self.assertEqual(r["evidence"]["old_key_before"], True)
        self.assertEqual(r["evidence"]["old_key_after"], "DENIED")
        self.assertEqual(r["evidence"]["new_key_after"], "GRANTED")

    def test_brute_force_locked_out(self):
        r = self.sim.brute_force()
        self._assert_blocked(r)
        results = [a["result"] for a in r["evidence"]["attempts"]]
        self.assertEqual(results.count("WRONG"), 5)
        self.assertIn("LOCKED_OUT", results)
        self.assertNotIn("CORRECT", results)
        self.assertGreater(r["evidence"]["slowdown_factor"], 1000)

    def test_timing_leak_mitigated(self):
        r = self.sim.timing_leak()
        self._assert_blocked(r)
        self.assertGreater(r["evidence"]["naive_gap_ms"], r["evidence"]["mitigated_gap_ms"])

    def test_registry_matches_catalog(self):
        self.assertEqual(set(self.sim.registry()), {a["id"] for a in ATTACK_CATALOG})


class TestRateLimiter(unittest.TestCase):
    def test_lockout_after_max_failures_and_expiry(self):
        now = [1000.0]
        lim = LoginRateLimiter(max_failures=3, window_seconds=60, lockout_seconds=30, clock=lambda: now[0])
        self.assertFalse(lim.register_failure("Alice", "1.1.1.1"))
        self.assertFalse(lim.register_failure("alice", "1.1.1.1"))  # case-insensitive
        self.assertTrue(lim.register_failure("alice", "1.1.1.1"))
        self.assertGreater(lim.retry_after("alice", "1.1.1.1"), 0)
        # A different IP is unaffected (no lockout-DoS against the real user)
        self.assertEqual(lim.retry_after("alice", "2.2.2.2"), 0)
        now[0] += 31
        self.assertEqual(lim.retry_after("alice", "1.1.1.1"), 0)

    def test_failures_outside_window_are_forgotten(self):
        now = [0.0]
        lim = LoginRateLimiter(max_failures=3, window_seconds=10, lockout_seconds=30, clock=lambda: now[0])
        lim.register_failure("bob", "ip")
        lim.register_failure("bob", "ip")
        now[0] += 11
        self.assertFalse(lim.register_failure("bob", "ip"))

    def test_success_resets(self):
        lim = LoginRateLimiter(max_failures=2)
        lim.register_failure("c", "ip")
        lim.register_success("c", "ip")
        self.assertFalse(lim.register_failure("c", "ip"))


class TestAuthHardeningAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app = create_app()
        app.config["TESTING"] = True
        initialise_services(app)
        cls.client = app.test_client()
        login_limiter.reset()

        # Bootstrap: first registration is allowed and forced to admin
        r = cls.client.post("/api/auth/register", json={
            "username": "root", "password": "Root@2026!", "system_role": "user",
        })
        assert r.status_code == 201, r.get_data(as_text=True)
        cls.admin_token = r.get_json()["token"]
        assert r.get_json()["user"]["system_role"] == "admin"

        r = cls.client.post("/api/auth/register", json={
            "username": "eve", "password": "Eve@2026!",
            "role_attr": "Role:Student", "clearance_attr": "Clearance:Level-1",
        }, headers={"Authorization": f"Bearer {cls.admin_token}"})
        assert r.status_code == 201, r.get_data(as_text=True)
        cls.eve_token = r.get_json()["token"]

    def setUp(self):
        login_limiter.reset()

    def test_anonymous_registration_refused(self):
        r = self.client.post("/api/auth/register", json={
            "username": "mallory", "password": "Mallory!1",
            "clearance_attr": "Clearance:Level-3", "system_role": "admin",
        })
        self.assertEqual(r.status_code, 403)

    def test_non_admin_cannot_enrol_users(self):
        r = self.client.post("/api/auth/register", json={
            "username": "mallory2", "password": "Mallory!1", "clearance_attr": "Clearance:Level-3",
        }, headers={"Authorization": f"Bearer {self.eve_token}"})
        self.assertEqual(r.status_code, 403)

    def test_invalid_system_role_rejected(self):
        r = self.client.post("/api/auth/register", json={
            "username": "weird", "password": "Weird@2026!", "system_role": "superuser",
        }, headers={"Authorization": f"Bearer {self.admin_token}"})
        self.assertEqual(r.status_code, 400)

    def test_login_lockout_returns_429(self):
        for _ in range(5):
            r = self.client.post("/api/auth/login", json={"username": "eve", "password": "nope"})
            self.assertEqual(r.status_code, 401)
        # Even the correct password is refused while locked out
        r = self.client.post("/api/auth/login", json={"username": "eve", "password": "Eve@2026!"})
        self.assertEqual(r.status_code, 429)
        self.assertIn("Retry-After", r.headers)

    def test_unknown_user_gets_same_401(self):
        r1 = self.client.post("/api/auth/login", json={"username": "ghost", "password": "x"})
        r2 = self.client.post("/api/auth/login", json={"username": "eve", "password": "x"})
        self.assertEqual(r1.status_code, 401)
        self.assertEqual(r1.get_json(), r2.get_json())

    def test_attack_endpoints(self):
        h = {"Authorization": f"Bearer {self.eve_token}"}
        r = self.client.get("/api/attacks", headers=h)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.get_json()["attacks"]), len(ATTACK_CATALOG))
        r = self.client.post("/api/attacks/collusion/run", headers=h)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["outcome"], "BLOCKED")
        self.assertEqual(self.client.post("/api/attacks/nope/run", headers=h).status_code, 404)
        self.assertEqual(self.client.post("/api/attacks/collusion/run").status_code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
