"""
KeyStore: Secure Envelope Storage for Master Secret Keys and User Private Keys.
- Never stores plaintext keys on disk or database.
- Uses AES-256-GCM authenticated encryption.
- Derives 256-bit Key Encryption Keys (KEK) using PBKDF2-HMAC-SHA256 with random 16-byte salts.
"""
import base64
import json
import os
from typing import Any, Dict
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

from .charm_engine import CharmEngine


class KeyStore:
    def __init__(self, engine: CharmEngine = None):
        self.engine = engine if engine is not None else CharmEngine()

    @staticmethod
    def _derive_kek(passphrase: str, salt: bytes) -> bytes:
        """
        Derive a 256-bit Key Encryption Key from a passphrase using PBKDF2-SHA256.
        """
        return PBKDF2(passphrase, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)

    def encrypt_key_object(self, key_obj: Any, passphrase: str) -> Dict[str, str]:
        """
        Serialize and encrypt any Charm key object (MK or SK) using AES-256-GCM.
        """
        serialized = self.engine.serialize(key_obj).encode('utf-8')
        salt = os.urandom(16)
        kek = self._derive_kek(passphrase, salt)

        cipher = AES.new(kek, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(serialized)

        return {
            "version": "1.0",
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": 100000,
            "salt": base64.b64encode(salt).decode('ascii'),
            "nonce": base64.b64encode(cipher.nonce).decode('ascii'),
            "tag": base64.b64encode(tag).decode('ascii'),
            "ciphertext": base64.b64encode(ciphertext).decode('ascii')
        }

    def decrypt_key_object(self, envelope: Dict[str, Any], passphrase: str) -> Any:
        """
        Decrypt and deserialize a Charm key object from an encrypted envelope.
        Raises ValueError if the passphrase is incorrect or the ciphertext is tampered.
        """
        try:
            salt = base64.b64decode(envelope["salt"].encode('ascii'))
            nonce = base64.b64decode(envelope["nonce"].encode('ascii'))
            tag = base64.b64decode(envelope["tag"].encode('ascii'))
            ciphertext = base64.b64decode(envelope["ciphertext"].encode('ascii'))

            kek = self._derive_kek(passphrase, salt)
            cipher = AES.new(kek, AES.MODE_GCM, nonce=nonce)
            serialized = cipher.decrypt_and_verify(ciphertext, tag)
            return self.engine.deserialize(serialized.decode('utf-8'))
        except (ValueError, KeyError) as e:
            raise ValueError(
                "Key Decryption Failed: Invalid passphrase or corrupted key store."
            ) from e

    def save_master_key(self, mk: Any, file_path: str, passphrase: str) -> None:
        """
        Save the Master Secret Key encrypted at rest to a file.
        """
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        envelope = self.encrypt_key_object(mk, passphrase)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(envelope, f, indent=2)

    def load_master_key(self, file_path: str, passphrase: str) -> Any:
        """
        Load and decrypt the Master Secret Key from disk.
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            envelope = json.load(f)
        return self.decrypt_key_object(envelope, passphrase)

    def save_public_key(self, pk: Any, file_path: str) -> None:
        """
        Save the Public Key (public parameters) to disk as JSON.
        """
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        data = {"public_parameters": self.engine.serialize(pk)}
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    def load_public_key(self, file_path: str) -> Any:
        """
        Load the Public Key from disk.
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return self.engine.deserialize(data["public_parameters"])

    def encrypt_user_key(self, sk: Any, user_passphrase: str) -> str:
        """
        Returns JSON string of encrypted user key suitable for SQLite storage or keyfile export.
        """
        envelope = self.encrypt_key_object(sk, user_passphrase)
        return json.dumps(envelope)

    def decrypt_user_key(self, encrypted_json: str, user_passphrase: str) -> Any:
        """
        Recovers user private key object in memory using user passphrase.
        """
        envelope = json.loads(encrypted_json)
        return self.decrypt_key_object(envelope, user_passphrase)
