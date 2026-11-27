"""
Unit Test: Genuine Charm-Crypto BSW07 CP-ABE Mathematical Primitives
"""
import unittest
import sys
import os

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto.charm_engine import CharmEngine


class TestCharmBSW07(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = CharmEngine(curve="BN254")
        cls.pk, cls.mk = cls.engine.setup()

    def test_setup(self):
        """Verify public parameters and master secret key generation."""
        self.assertIsNotNone(self.pk)
        self.assertIsNotNone(self.mk)
        self.assertIn('g', self.pk)
        self.assertIn('h', self.pk)
        self.assertIn('e_gg_alpha', self.pk)
        self.assertIn('beta', self.mk)

    def test_keygen_and_decryption(self):
        """Verify keygen and decryption with matching attributes."""
        attrs = ["ROLE:ENGINEER", "CLEARANCE:LEVEL-3"]
        sk = self.engine.keygen(self.pk, self.mk, attrs)
        self.assertIsNotNone(sk)
        self.assertIn('D', sk)
        self.assertIn('Dj', sk)

        policy = "ROLE:ENGINEER and CLEARANCE:LEVEL-3"
        secret_m = self.engine.random_message()
        ct, formatted_policy = self.engine.encrypt(self.pk, secret_m, policy)

        recovered = self.engine.decrypt(self.pk, sk, ct)
        self.assertEqual(secret_m, recovered, "Decrypted message must match original secret element.")

    def test_serialization(self):
        """Verify serialization and deserialization of cryptographic objects."""
        attrs = ["ROLE:MANAGER", "CLEARANCE:LEVEL-3"]
        sk = self.engine.keygen(self.pk, self.mk, attrs)

        # Test pk & sk serialization
        pk_str = self.engine.serialize(self.pk)
        sk_str = self.engine.serialize(sk)
        self.assertIsInstance(pk_str, str)
        self.assertIsInstance(sk_str, str)

        restored_pk = self.engine.deserialize(pk_str)
        restored_sk = self.engine.deserialize(sk_str)

        secret_m = self.engine.random_message()
        ct, _ = self.engine.encrypt(restored_pk, secret_m, "ROLE:MANAGER and CLEARANCE:LEVEL-3")

        # Test ct serialization
        ct_str = self.engine.serialize(ct)
        restored_ct = self.engine.deserialize(ct_str)

        recovered = self.engine.decrypt(restored_pk, restored_sk, restored_ct)
        self.assertEqual(secret_m, recovered)


if __name__ == '__main__':
    unittest.main(verbosity=2)
