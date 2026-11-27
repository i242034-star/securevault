"""
Hybrid Cipher Test:
- Tests AES-256-GCM + CP-ABE hybrid encryption on an actual PDF document.
- Verifies Alice and Charlie recover identical PDF bytes.
- Verifies Bob and David are denied by CP-ABE (AccessDeniedError).
- Verifies AES-GCM authentication detects all forms of ciphertext/tag tampering.
"""
import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto.charm_engine import CharmEngine
from crypto.hybrid_cipher import HybridCipher, AccessDeniedError, TamperError


class TestHybridCipher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = CharmEngine(curve="BN254")
        cls.hybrid = HybridCipher(cls.engine)
        cls.pk, cls.mk = cls.engine.setup()

        # Read actual PDF test document
        cls.pdf_path = os.path.join(os.path.dirname(__file__), "sample_confidential.pdf")
        with open(cls.pdf_path, "rb") as f:
            cls.original_pdf_bytes = f.read()

        cls.original_sha256 = hashlib.sha256(cls.original_pdf_bytes).hexdigest()

        # Core Access Policy
        cls.policy = "(Role:Engineer OR Role:Manager) AND Clearance:Level-3"

        # Encrypt the PDF
        cls.encrypted_package = cls.hybrid.encrypt_document(
            cls.pk, cls.original_pdf_bytes, cls.policy
        )

        # Generate keys for test users
        cls.sk_alice = cls.engine.keygen(cls.pk, cls.mk, ["Role:Engineer", "Clearance:Level-3"])
        cls.sk_charlie = cls.engine.keygen(cls.pk, cls.mk, ["Role:Manager", "Clearance:Level-3"])
        cls.sk_bob = cls.engine.keygen(cls.pk, cls.mk, ["Role:Student", "Clearance:Level-3"])
        cls.sk_david = cls.engine.keygen(cls.pk, cls.mk, ["Role:Engineer", "Clearance:Level-2"])

    def test_alice_pdf_decryption(self):
        """Alice must recover the exact original PDF document."""
        decrypted_bytes = self.hybrid.decrypt_document(self.pk, self.sk_alice, self.encrypted_package)
        decrypted_sha256 = hashlib.sha256(decrypted_bytes).hexdigest()
        self.assertEqual(decrypted_sha256, self.original_sha256)
        self.assertTrue(decrypted_bytes.startswith(b"%PDF-1.4"))

    def test_charlie_pdf_decryption(self):
        """Charlie must recover the exact original PDF document."""
        decrypted_bytes = self.hybrid.decrypt_document(self.pk, self.sk_charlie, self.encrypted_package)
        decrypted_sha256 = hashlib.sha256(decrypted_bytes).hexdigest()
        self.assertEqual(decrypted_sha256, self.original_sha256)

    def test_bob_access_denied(self):
        """Bob must be denied at the CP-ABE layer with AccessDeniedError."""
        with self.assertRaises(AccessDeniedError):
            self.hybrid.decrypt_document(self.pk, self.sk_bob, self.encrypted_package)

    def test_david_access_denied(self):
        """David must be denied at the CP-ABE layer with AccessDeniedError."""
        with self.assertRaises(AccessDeniedError):
            self.hybrid.decrypt_document(self.pk, self.sk_david, self.encrypted_package)

    def test_ciphertext_tampering_triggers_error(self):
        """Tampering with AES ciphertext bytes must trigger TamperError via AES-GCM tag verification."""
        import base64
        tampered_package = dict(self.encrypted_package)
        raw_ct = bytearray(base64.b64decode(tampered_package["aes_ciphertext"]))
        raw_ct[10] ^= 0xFF  # Flip bits in ciphertext
        tampered_package["aes_ciphertext"] = base64.b64encode(raw_ct).decode("ascii")

        with self.assertRaises(TamperError):
            self.hybrid.decrypt_document(self.pk, self.sk_alice, tampered_package)

    def test_tag_tampering_triggers_error(self):
        """Tampering with AES-GCM authentication tag must trigger TamperError."""
        import base64
        tampered_package = dict(self.encrypted_package)
        raw_tag = bytearray(base64.b64decode(tampered_package["tag"]))
        raw_tag[0] ^= 0x01  # Alter tag
        tampered_package["tag"] = base64.b64encode(raw_tag).decode("ascii")

        with self.assertRaises(TamperError):
            self.hybrid.decrypt_document(self.pk, self.sk_alice, tampered_package)


if __name__ == '__main__':
    unittest.main(verbosity=2)
