"""
HybridCipher: Combines genuine BSW07 CP-ABE with AES-256-GCM.
- CP-ABE protects the 256-bit AES key (KEM) under an access policy tree.
- AES-256-GCM provides authenticated, tamper-proof document encryption (DEM).
"""
import base64
import hashlib
from typing import Any, Dict
from Crypto.Cipher import AES

from .charm_engine import CharmEngine


class AccessDeniedError(Exception):
    """Raised when CP-ABE decryption fails because user attributes do not satisfy the policy."""
    pass


class TamperError(Exception):
    """Raised when AES-GCM tag verification fails due to data corruption or tampering."""
    pass


class HybridCipher:
    def __init__(self, engine: CharmEngine = None):
        self.engine = engine if engine is not None else CharmEngine()

    @staticmethod
    def _derive_aes_key(kem_secret: Any) -> bytes:
        """
        Derive a cryptographically secure 256-bit AES key from the group GT element.
        """
        # String representation of the GT element hashed via SHA-256
        return hashlib.sha256(str(kem_secret).encode('utf-8')).digest()

    def encrypt_document(self, pk: Any, file_bytes: bytes, policy_str: str) -> Dict[str, str]:
        """
        Encrypt document bytes using AES-256-GCM and protect the AES key via CP-ABE.
        Returns a dictionary containing all ciphertext components (base64 encoded).
        """
        # 1. Generate random GT element for KEM
        kem_secret = self.engine.random_message()

        # 2. Derive 256-bit AES key
        aes_key = self._derive_aes_key(kem_secret)

        # 3. Encrypt document with AES-256-GCM
        cipher = AES.new(aes_key, AES.MODE_GCM)
        aes_ciphertext, tag = cipher.encrypt_and_digest(file_bytes)
        nonce = cipher.nonce

        # 4. Encrypt the KEM secret under the access policy via CP-ABE
        ct, formatted_policy = self.engine.encrypt(pk, kem_secret, policy_str)

        # 5. Return package
        return {
            "cpabe_ciphertext": self.engine.serialize(ct),
            "aes_ciphertext": base64.b64encode(aes_ciphertext).decode('ascii'),
            "nonce": base64.b64encode(nonce).decode('ascii'),
            "tag": base64.b64encode(tag).decode('ascii'),
            "policy": formatted_policy,
        }

    def decrypt_document(self, pk: Any, sk: Any, encrypted_package: Dict[str, str]) -> bytes:
        """
        Decrypt document:
        1. Recover the KEM secret via CP-ABE using the user private key.
        2. If CP-ABE fails, raise AccessDeniedError (no key recovered).
        3. Derive the AES key and decrypt the document via AES-256-GCM.
        4. If the ciphertext or tag has been tampered with, raise TamperError.
        """
        # 1. Deserialize CP-ABE ciphertext
        ct = self.engine.deserialize(encrypted_package["cpabe_ciphertext"])

        # 2. Attempt CP-ABE decryption
        kem_secret = self.engine.decrypt(pk, sk, ct)
        if kem_secret is None:
            raise AccessDeniedError(
                "Access Denied: The cryptographic attributes in your private key do not satisfy the document access policy."
            )

        # 3. Derive 256-bit AES key
        aes_key = self._derive_aes_key(kem_secret)

        # 4. Decode AES components
        aes_ciphertext = base64.b64decode(encrypted_package["aes_ciphertext"].encode('ascii'))
        nonce = base64.b64decode(encrypted_package["nonce"].encode('ascii'))
        tag = base64.b64decode(encrypted_package["tag"].encode('ascii'))

        # 5. Decrypt and verify document
        try:
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            plaintext_bytes = cipher.decrypt_and_verify(aes_ciphertext, tag)
            return plaintext_bytes
        except (ValueError, KeyError) as e:
            raise TamperError(
                "Integrity Verification Failed: AES-256-GCM authentication tag mismatch. "
                "The ciphertext has been corrupted or maliciously modified."
            ) from e
