"""
KeyStore Test:
- Verifies envelope encryption of Master Secret Key and User Private Keys at rest.
- Verifies correct recovery with legitimate passphrase.
- Verifies rejection when supplied with wrong passphrase or tampered ciphertext.
- Verifies cryptographic operational validity of recovered keys.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto.charm_engine import CharmEngine
from crypto.key_store import KeyStore


class TestKeyStore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = CharmEngine(curve="BN254")
        cls.key_store = KeyStore(cls.engine)
        cls.pk, cls.mk = cls.engine.setup()

    def test_master_key_envelope_storage_and_recovery(self):
        """Master key must be encrypted at rest and recoverable only with correct passphrase."""
        with tempfile.NamedTemporaryFile(suffix=".keystore", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            passphrase = "Authority_Secure_Passphrase_2026!"
            self.key_store.save_master_key(self.mk, tmp_path, passphrase)

            # Inspect stored file: verify it is JSON with salt, nonce, tag, ciphertext
            with open(tmp_path, "r", encoding="utf-8") as f:
                stored_data = json.load(f)
            self.assertIn("ciphertext", stored_data)
            self.assertIn("salt", stored_data)
            self.assertIn("tag", stored_data)
            # Ensure plaintext components like 'beta' are NOT present in plaintext keys
            self.assertNotIn("beta", stored_data)

            # Correct recovery
            recovered_mk = self.key_store.load_master_key(tmp_path, passphrase)
            self.assertIsNotNone(recovered_mk)

            # Verify the recovered MK is cryptographically functional (can issue keys)
            test_sk = self.engine.keygen(self.pk, recovered_mk, ["Role:Engineer", "Clearance:Level-3"])
            self.assertIsNotNone(test_sk)

            # Incorrect passphrase must fail
            with self.assertRaises(ValueError):
                self.key_store.load_master_key(tmp_path, "WrongPassphrase123")

        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_user_key_envelope_encryption(self):
        """User private keys must be encrypted at rest and recoverable with user passphrase."""
        user_passphrase = "AliceUserPassword#789"
        sk = self.engine.keygen(self.pk, self.mk, ["Role:Engineer", "Clearance:Level-3"])

        encrypted_json = self.key_store.encrypt_user_key(sk, user_passphrase)
        self.assertIsInstance(encrypted_json, str)
        envelope = json.loads(encrypted_json)
        self.assertIn("ciphertext", envelope)
        self.assertIn("salt", envelope)
        self.assertIn("tag", envelope)
        # Verify no plaintext attributes or key dictionaries are exposed
        self.assertNotIn("CLEARANCE_LEVEL3", encrypted_json)
        self.assertNotIn("ROLE_ENGINEER", encrypted_json)

        # Correct recovery
        recovered_sk = self.key_store.decrypt_user_key(encrypted_json, user_passphrase)
        self.assertIsNotNone(recovered_sk)

        # Functional test: recovered key can decrypt CP-ABE ciphertext
        secret_m = self.engine.random_message()
        ct, _ = self.engine.encrypt(self.pk, secret_m, "Role:Engineer and Clearance:Level-3")
        recovered_m = self.engine.decrypt(self.pk, recovered_sk, ct)
        self.assertEqual(secret_m, recovered_m)

        # Incorrect passphrase must fail
        with self.assertRaises(ValueError):
            self.key_store.decrypt_user_key(encrypted_json, "WrongPassword")

    def test_tampered_key_envelope_rejected(self):
        """Tampering with an encrypted key envelope must be detected and rejected."""
        sk = self.engine.keygen(self.pk, self.mk, ["Role:Manager", "Clearance:Level-3"])
        encrypted_json = self.key_store.encrypt_user_key(sk, "TestPass")
        data = json.loads(encrypted_json)

        # Tamper with tag
        data["tag"] = "AAAA" + data["tag"][4:]
        tampered_json = json.dumps(data)

        with self.assertRaises(ValueError):
            self.key_store.decrypt_user_key(tampered_json, "TestPass")


if __name__ == '__main__':
    unittest.main(verbosity=2)
