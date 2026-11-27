"""
CharmEngine: Wrapper for genuine Charm-Crypto BSW07 CP-ABE scheme.
Uses Stanford PBC library and BN254 pairing-friendly elliptic curve.
"""
import base64
import re
from typing import Any, List, Optional, Tuple
from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import objectToBytes, bytesToObject

try:  # Charm >= 0.6x seals BSW07 ciphertexts with an AEAD integrity tag
    from charm.toolbox.abeintegrity import InvalidCiphertext
except ImportError:  # older Charm builds have no integrity wrapper
    class InvalidCiphertext(Exception):
        pass


class CharmEngine:
    def __init__(self, curve: str = "BN254"):
        """
        Initialize the CP-ABE scheme using the specified pairing-friendly elliptic curve.
        Default curve is 'BN254' (NIST 128-bit security level).
        """
        self.curve = curve
        self.group = PairingGroup(curve)
        self.cpabe = CPabe_BSW07(self.group)

    @staticmethod
    def format_attribute(attr: str) -> str:
        """
        Standardize attribute strings for Charm's policy parser:
        - Uppercase
        - Replace ':' or '-' or whitespace with '_'
        - Strip underscore before digits (e.g. 'LEVEL_3' -> 'LEVEL3') because Charm
          reserves '_<digit>' for attribute index occurrences in secret sharing.
        """
        cleaned = attr.strip().upper()
        cleaned = re.sub(r'[:\s\-]+', '_', cleaned)
        # Avoid _ followed by digit at the end or within (e.g. LEVEL_3 -> LEVEL3)
        cleaned = re.sub(r'_(\d+)', r'\1', cleaned)
        # Strip any remaining illegal characters
        cleaned = re.sub(r'[^A-Z0-9_]', '', cleaned)
        return cleaned

    @staticmethod
    def format_policy(policy_str: str) -> str:
        """
        Standardize policy strings for Charm's policy tree parser:
        - Boolean operators must be lowercase 'and', 'or', 'of'
        - Attribute tokens are formatted via format_attribute
        """
        # Tokenize preserving parentheses
        tokens = re.split(r'(\(|\)|\s+)', policy_str)
        formatted_tokens = []
        for t in tokens:
            if not t or t.isspace():
                formatted_tokens.append(t)
            elif t in ('(', ')'):
                formatted_tokens.append(t)
            elif t.upper() in ('AND', 'OR', 'OF'):
                formatted_tokens.append(t.lower())
            else:
                formatted_tokens.append(CharmEngine.format_attribute(t))
        return ''.join(formatted_tokens)

    def setup(self) -> Tuple[Any, Any]:
        """
        Generate public parameters (pk) and master secret key (mk).
        """
        return self.cpabe.setup()

    def keygen(self, pk: Any, mk: Any, attributes: List[str]) -> Any:
        """
        Generate a cryptographic private key (sk) bound to the assigned user attributes.
        """
        formatted_attrs = [self.format_attribute(a) for a in attributes if a.strip()]
        return self.cpabe.keygen(pk, mk, formatted_attrs)

    def random_message(self) -> Any:
        """
        Generate a random element M in group GT to serve as the KEM secret.
        """
        return self.group.random(GT)

    def encrypt(self, pk: Any, msg: Any, policy_str: str) -> Tuple[Any, str]:
        """
        Encrypt a group element M under the specified access policy.
        Returns (ciphertext, formatted_policy).
        """
        formatted_policy = self.format_policy(policy_str)
        ct = self.cpabe.encrypt(pk, msg, formatted_policy)
        return ct, formatted_policy

    def decrypt(self, pk: Any, sk: Any, ct: Any) -> Optional[Any]:
        """
        Decrypt the ciphertext using the user private key.
        Returns the recovered group element M if attributes satisfy the policy,
        or None if access is denied.
        """
        recovered, _reason = self.decrypt_detailed(pk, sk, ct)
        return recovered

    def decrypt_detailed(self, pk: Any, sk: Any, ct: Any) -> Tuple[Optional[Any], str]:
        """
        Decrypt and report *why* a decryption failed. Returns (M or None, reason):
          - "OK"                 : attributes satisfied the policy, M recovered.
          - "POLICY_UNSATISFIED" : the key's attribute set cannot satisfy the
                                   access tree (Charm prunes the tree -> False).
          - "PAIRING_MISMATCH"   : the attribute labels looked satisfying but the
                                   pairing reconstruction produced a wrong session
                                   element, so Charm's ciphertext integrity seal
                                   rejected it. This is what happens to colluding
                                   (merged) keys, forged keys and tampered ciphertexts.
          - "MALFORMED"          : structurally invalid key/ciphertext.
        """
        try:
            recovered = self.cpabe.decrypt(pk, sk, ct)
        except InvalidCiphertext:
            return None, "PAIRING_MISMATCH"
        except (KeyError, TypeError, ValueError, AttributeError):
            return None, "MALFORMED"
        if recovered is False or recovered is None:
            return None, "POLICY_UNSATISFIED"
        return recovered, "OK"

    def serialize(self, obj: Any) -> str:
        """
        Serialize any Charm cryptographic object (pk, mk, sk, ct) to base64 string.
        """
        raw_bytes = objectToBytes(obj, self.group)
        return base64.b64encode(raw_bytes).decode('ascii')

    def deserialize(self, b64_str: str) -> Any:
        """
        Deserialize a base64 string back into a Charm cryptographic object.
        """
        raw_bytes = base64.b64decode(b64_str.encode('ascii'))
        return bytesToObject(raw_bytes, self.group)
