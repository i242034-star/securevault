"""
CryptoService: Orchestrates BSW07 CP-ABE, Hybrid AES-256-GCM, and Key Store
Manages Trusted Authority lifecycle, key issuance, document encryption,
authorized decryption, dynamic attribute management, and epoch-based revocation.
"""
import base64
import json
import os
import sys
import uuid
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import config
from crypto.charm_engine import CharmEngine
from crypto.hybrid_cipher import HybridCipher, AccessDeniedError, TamperError
from crypto.key_store import KeyStore
from models.database import get_db
from utils.auth import verify_password


class CryptoService:
    _instance = None

    def __init__(self):
        self.engine = CharmEngine(curve="BN254")
        self.hybrid = HybridCipher(self.engine)
        self.key_store = KeyStore(self.engine)
        self.pk = None
        self._mk = None  # Protected in-memory master secret key
        self._initialize_authority()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = CryptoService()
        return cls._instance

    def _initialize_authority(self):
        """
        Initialize or load the Trusted Authority's Master Secret Key and Public Parameters.
        """
        if os.path.exists(config.MASTER_KEY_PATH) and os.path.exists(config.PUBLIC_KEY_PATH):
            try:
                self.pk = self.key_store.load_public_key(config.PUBLIC_KEY_PATH)
                self._mk = self.key_store.load_master_key(config.MASTER_KEY_PATH, config.MASTER_KEY_PASSPHRASE)
                return
            except Exception as e:
                print(f"[!] Warning: Could not load existing authority keys ({e}). Re-initializing authority.")

        # Perform fresh CP-ABE setup
        self.pk, self._mk = self.engine.setup()
        self.key_store.save_public_key(self.pk, config.PUBLIC_KEY_PATH)
        self.key_store.save_master_key(self._mk, config.MASTER_KEY_PATH, config.MASTER_KEY_PASSPHRASE)
        print("[+] Trusted Authority initialized. Public parameters and encrypted Master Key saved.")

    def log_audit(self, user_id: Optional[int], username: str, action: str, status: str, details: str = "", ip_address: str = None):
        """
        Record a tamper-evident security audit log entry in SQLite linked into
        the cryptographic HMAC-SHA256 hash chain.
        """
        from crypto.audit_chain import record_audit_event
        conn = get_db()
        try:
            return record_audit_event(
                conn=conn,
                user_id=user_id,
                username=username,
                action=action,
                status=status,
                details=details,
                ip_address=ip_address or "127.0.0.1",
            )
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # Epoch Management (Phase 4)                                         #
    # ------------------------------------------------------------------ #
    def get_current_epoch(self) -> int:
        """
        Return the current active system epoch number. Defaults to 1 if unseeded.
        """
        conn = get_db()
        try:
            row = conn.execute("SELECT MAX(epoch_number) AS cur_epoch FROM system_epochs").fetchone()
            if row and row["cur_epoch"]:
                return int(row["cur_epoch"])
            return 1
        finally:
            conn.close()

    def get_current_epoch_info(self) -> Dict[str, Any]:
        """
        Retrieve comprehensive epoch state: active epoch, rotation lifecycle,
        re-encryption progress, and historical epoch changes.
        """
        conn = get_db()
        try:
            cur_epoch = self.get_current_epoch()
            current_row = conn.execute(
                "SELECT * FROM system_epochs WHERE epoch_number = ?", (cur_epoch,)
            ).fetchone()

            history_rows = conn.execute(
                "SELECT * FROM system_epochs ORDER BY epoch_number DESC"
            ).fetchall()

            # Document epoch counts
            total_docs = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
            current_epoch_docs = conn.execute(
                "SELECT COUNT(*) FROM documents WHERE epoch = ?", (cur_epoch,)
            ).fetchone()[0]
            legacy_docs = conn.execute(
                "SELECT COUNT(*) FROM documents WHERE epoch = 0"
            ).fetchone()[0]
            prior_epoch_docs = conn.execute(
                "SELECT COUNT(*) FROM documents WHERE epoch > 0 AND epoch < ?", (cur_epoch,)
            ).fetchone()[0]

            # User key claim status
            users_with_pending = conn.execute(
                "SELECT COUNT(*) FROM users WHERE pending_key_reissue = 1"
            ).fetchone()[0]

            return {
                "current_epoch": cur_epoch,
                "status": current_row["status"] if current_row else "COMPLETED",
                "reason": current_row["reason"] if current_row else "System initial state",
                "initiated_by": current_row["initiated_by"] if current_row else "system",
                "created_at": current_row["created_at"] if current_row else None,
                "document_stats": {
                    "total_documents": total_docs,
                    "current_epoch_documents": current_epoch_docs,
                    "legacy_documents": legacy_docs,
                    "prior_epoch_documents": prior_epoch_docs,
                },
                "user_key_stats": {
                    "users_with_pending_keys": users_with_pending,
                },
                "history": [dict(r) for r in history_rows]
            }
        finally:
            conn.close()

    def advance_system_epoch(self, admin_id: int, admin_username: str, reason: str, ip_address: str = None) -> int:
        """
        Advance the system epoch: Stage 1 of the Epoch Rotation Lifecycle.
        Increments the global epoch number and records the reason in audit logs.
        Does NOT claim revocation is completed until documents are re-encrypted.
        """
        conn = get_db()
        try:
            cur_epoch = self.get_current_epoch()
            new_epoch = cur_epoch + 1

            conn.execute(
                "INSERT INTO system_epochs (epoch_number, reason, initiated_by, status) VALUES (?, ?, ?, 'DECLARED')",
                (new_epoch, reason, admin_username)
            )

            # Flag all non-admin users as having a pending key reissue for the new epoch
            conn.execute("UPDATE users SET pending_key_reissue = 1 WHERE system_role != 'admin'")
            conn.commit()

            self.log_audit(
                user_id=admin_id,
                username=admin_username,
                action="EPOCH_ADVANCED",
                status="SUCCESS",
                details=f"System epoch advanced from {cur_epoch} to {new_epoch}. Reason: {reason}",
                ip_address=ip_address
            )

            return new_epoch
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # Dynamic Attribute & Key Management (Phase 4)                       #
    # ------------------------------------------------------------------ #
    def issue_user_key(self, user_id: int, username: str, attributes: List[str], user_passphrase: str, ip_address: str = None, include_epoch: bool = False) -> Dict[str, Any]:
        """
        Trusted Authority operation:
        Generate a genuine BSW07 cryptographic private key bound to the assigned attributes.
        Envelope-encrypts the private key with user's verified passphrase.
        """
        if not self._mk:
            raise RuntimeError("Master authority key is not loaded.")

        # Clean attributes and append Epoch attribute if requested or if epoch policies are used
        cleaned_attrs = list(dict.fromkeys([a.strip() for a in attributes if a.strip()]))
        if include_epoch:
            epoch_tag = f"Epoch:{self.get_current_epoch()}"
            if not any(a.lower().startswith("epoch:") for a in cleaned_attrs):
                cleaned_attrs.append(epoch_tag)

        conn = get_db()
        try:
            # 1. Determine key version
            row = conn.execute(
                "SELECT COALESCE(MAX(key_version), 0) + 1 AS next_ver FROM user_keys WHERE user_id = ?",
                (user_id,)
            ).fetchone()
            next_version = row["next_ver"]

            # 2. Deactivate previous active keys
            conn.execute("UPDATE user_keys SET is_active = 0 WHERE user_id = ?", (user_id,))

            # 3. Generate genuine CP-ABE private key via Charm-Crypto BSW07
            sk = self.engine.keygen(self.pk, self._mk, cleaned_attrs)

            # 4. Envelope-encrypt private key with user passphrase
            encrypted_sk_json = self.key_store.encrypt_user_key(sk, user_passphrase)

            # 5. Store in user_keys table
            cursor = conn.execute(
                "INSERT INTO user_keys (user_id, key_version, bound_attributes, encrypted_sk, is_active) VALUES (?, ?, ?, ?, 1)",
                (user_id, next_version, json.dumps(cleaned_attrs), encrypted_sk_json)
            )
            key_id = cursor.lastrowid

            # 6. Clear pending_key_reissue flag
            conn.execute("UPDATE users SET pending_key_reissue = 0 WHERE id = ?", (user_id,))
            conn.commit()

            # 7. Audit log
            self.log_audit(
                user_id=user_id,
                username=username,
                action="KEY_ISSUANCE",
                status="SUCCESS",
                details=f"Issued key v{next_version} bound to attributes: {cleaned_attrs}",
                ip_address=ip_address
            )

            return {
                "key_id": key_id,
                "version": next_version,
                "bound_attributes": cleaned_attrs,
                "status": "ACTIVE"
            }
        finally:
            conn.close()

    def claim_pending_key(self, user_id: int, user_passphrase: str, ip_address: str = None) -> Dict[str, Any]:
        """
        Asynchronous user key claim:
        The authorized user provides their OWN password to retrieve and envelope-encrypt
        their updated private key embedding the current epoch and updated attributes.
        The administrator never learns or handles the user's password.
        """
        conn = get_db()
        try:
            user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if not user:
                raise ValueError("User does not exist.")

            # Verify password
            if not verify_password(user_passphrase, user["password_hash"]):
                raise ValueError("Invalid passphrase: could not verify identity to claim key.")

            custom_attrs = []
            if "custom_attributes" in user.keys() and user["custom_attributes"]:
                try:
                    custom_attrs = json.loads(user["custom_attributes"])
                except Exception:
                    custom_attrs = []

            all_attrs = [user["role_attr"], user["clearance_attr"]] + custom_attrs
            cur_epoch = self.get_current_epoch()
            all_attrs.append(f"Epoch:{cur_epoch}")

            return self.issue_user_key(
                user_id=user["id"],
                username=user["username"],
                attributes=all_attrs,
                user_passphrase=user_passphrase,
                ip_address=ip_address,
                include_epoch=True
            )
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # Document Encryption & Decryption                                   #
    # ------------------------------------------------------------------ #
    def encrypt_and_store_document(self, uploader_id: int, uploader_username: str, original_filename: str, file_bytes: bytes, policy_str: str, ip_address: str = None, attach_epoch: bool = False) -> Dict[str, Any]:
        """
        Hybrid encryption:
        Encrypts PDF with AES-256-GCM and protects the AES key via CP-ABE (KEM/DEM).
        Stores the AES ciphertext on disk and metadata in SQLite.
        """
        target_epoch = self.get_current_epoch() if attach_epoch else 0
        final_policy = policy_str
        if attach_epoch and f"Epoch:{target_epoch}" not in policy_str and f"EPOCH{target_epoch}" not in policy_str.upper():
            final_policy = f"({policy_str}) AND Epoch:{target_epoch}"

        # 1. Encrypt via hybrid cipher (KEM samples GT element M, derives AES key via SHA-256, encrypts PDF via AES-GCM)
        pkg = self.hybrid.encrypt_document(self.pk, file_bytes, final_policy)

        # 2. Save AES ciphertext blob to disk
        stored_filename = f"{uuid.uuid4().hex}.enc"
        file_disk_path = os.path.join(config.ENCRYPTED_DIR, stored_filename)

        raw_aes_ct = base64.b64decode(pkg["aes_ciphertext"].encode('ascii'))
        with open(file_disk_path, "wb") as f:
            f.write(raw_aes_ct)

        # 3. Save metadata to database
        conn = get_db()
        try:
            cursor = conn.execute(
                """
                INSERT INTO documents (
                    uploader_id, original_filename, stored_filename, file_size,
                    access_policy, formatted_policy, cpabe_ciphertext, aes_nonce, aes_tag, epoch
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    uploader_id, original_filename, stored_filename, len(file_bytes),
                    final_policy, pkg["policy"], pkg["cpabe_ciphertext"], pkg["nonce"], pkg["tag"], target_epoch
                )
            )
            doc_id = cursor.lastrowid
            conn.commit()

            # Audit log
            self.log_audit(
                user_id=uploader_id,
                username=uploader_username,
                action="DOC_UPLOAD",
                status="SUCCESS",
                details=f"Uploaded '{original_filename}' ({len(file_bytes)} bytes) encrypted under policy: {final_policy} (Epoch: {target_epoch})",
                ip_address=ip_address
            )

            return {
                "id": doc_id,
                "original_filename": original_filename,
                "file_size": len(file_bytes),
                "access_policy": final_policy,
                "formatted_policy": pkg["policy"],
                "stored_filename": stored_filename,
                "epoch": target_epoch
            }
        finally:
            conn.close()

    def decrypt_document(self, user_id: int, username: str, doc_id: int, user_passphrase: str, ip_address: str = None) -> Tuple[bytes, str]:
        """
        Authorized Decryption:
        1. Unlocks user's private key using their passphrase in transient memory.
        2. Performs actual CP-ABE decryption.
        3. If attributes fail policy, raises AccessDeniedError.
        4. If AES-GCM verification fails, raises TamperError.
        5. Logs audit trail and returns (decrypted_bytes, original_filename).
        """
        conn = get_db()
        try:
            # 1. Fetch document record
            doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
            if not doc:
                raise ValueError(f"Document with ID {doc_id} does not exist.")

            # 2. Fetch user's active key
            key_row = conn.execute(
                "SELECT * FROM user_keys WHERE user_id = ? AND is_active = 1 ORDER BY key_version DESC LIMIT 1",
                (user_id,)
            ).fetchone()
            if not key_row:
                self.log_audit(
                    user_id=user_id,
                    username=username,
                    action="DECRYPT_DENIED",
                    status="DENIED",
                    details=f"User has no active cryptographic key to decrypt document #{doc_id}",
                    ip_address=ip_address
                )
                raise AccessDeniedError("User does not have an active cryptographic private key.")

            bound_attrs = json.loads(key_row["bound_attributes"])

            # 3. Read AES ciphertext from disk
            disk_path = os.path.join(config.ENCRYPTED_DIR, doc["stored_filename"])
            if not os.path.exists(disk_path):
                raise FileNotFoundError("Encrypted document file is missing from secure storage.")

            with open(disk_path, "rb") as f:
                raw_aes_ct = f.read()

            # 4. Unlock user private key from encrypted envelope
            try:
                sk = self.key_store.decrypt_user_key(key_row["encrypted_sk"], user_passphrase)
            except ValueError as e:
                self.log_audit(
                    user_id=user_id,
                    username=username,
                    action="DECRYPT_FAILED",
                    status="FAILED",
                    details=f"Failed to unlock user private key: invalid password verification",
                    ip_address=ip_address
                )
                raise ValueError("Could not unlock private key: invalid passphrase.") from e

            # 5. Build encrypted package
            encrypted_pkg = {
                "cpabe_ciphertext": doc["cpabe_ciphertext"],
                "aes_ciphertext": base64.b64encode(raw_aes_ct).decode('ascii'),
                "nonce": doc["aes_nonce"],
                "tag": doc["aes_tag"]
            }

            # 6. Execute Hybrid Decryption (Genuine CP-ABE + AES-256-GCM)
            try:
                decrypted_bytes = self.hybrid.decrypt_document(self.pk, sk, encrypted_pkg)
            except AccessDeniedError as e:
                # CP-ABE bilinear pairing reconstruction failed mathematically
                self.log_audit(
                    user_id=user_id,
                    username=username,
                    action="DECRYPT_DENIED",
                    status="DENIED",
                    details=f"CP-ABE mathematical denial. Attributes {bound_attrs} do not satisfy policy: {doc['access_policy']}",
                    ip_address=ip_address
                )
                raise e
            except TamperError as e:
                self.log_audit(
                    user_id=user_id,
                    username=username,
                    action="DECRYPT_FAILED",
                    status="FAILED",
                    details=f"AES-256-GCM tag verification failure on document '{doc['original_filename']}'",
                    ip_address=ip_address
                )
                raise e

            # 7. Audit log success
            self.log_audit(
                user_id=user_id,
                username=username,
                action="DECRYPT_SUCCESS",
                status="SUCCESS",
                details=f"Successfully decrypted '{doc['original_filename']}' using key v{key_row['key_version']}",
                ip_address=ip_address
            )

            return decrypted_bytes, doc["original_filename"]
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # Secure Re-Encryption Workflow (Phase 4)                            #
    # ------------------------------------------------------------------ #
    def reencrypt_document(
        self,
        doc_id: int,
        reencryptor_user_id: int,
        reencryptor_username: str,
        reencryptor_passphrase: str,
        target_epoch: int = None,
        ip_address: str = None
    ) -> Dict[str, Any]:
        """
        Secure Document Re-encryption Workflow (Preserving KEM/DEM and CP-ABE Policy Enforcement):
        1. Enforces genuine CP-ABE decryption by re-encryptor identity (e.g. Data Custodian or authorized admin).
           If reencryptor's key does not mathematically satisfy the document's policy, AccessDeniedError is raised.
        2. Constructs updated policy embedding `Epoch:<target_epoch>`.
        3. Re-encrypts document bytes via Phase 1 HybridCipher (fresh random M, derived AES key, AES-256-GCM).
        4. Staged filesystem replacement:
           a. Write staged file (<new_uuid>.staged.enc) and verify.
           b. Rename staged file to final (<new_uuid>.enc).
           c. In SQLite transaction, update document record. Commit.
           d. If database error: delete new file, rollback, leave original intact.
           e. Only after commit success: delete old ciphertext file.
        5. Logs DOC_RE_ENCRYPTED in audit trail.
        """
        if target_epoch is None:
            target_epoch = self.get_current_epoch()

        # Step 1: Recover document bytes through authorized CP-ABE decryption
        decrypted_bytes, original_filename = self.decrypt_document(
            user_id=reencryptor_user_id,
            username=reencryptor_username,
            doc_id=doc_id,
            user_passphrase=reencryptor_passphrase,
            ip_address=ip_address
        )

        conn = get_db()
        try:
            doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
            old_stored_filename = doc["stored_filename"]
            base_policy = doc["access_policy"]

            # Remove any existing Epoch:... token to form updated policy cleanly
            import re
            cleaned_policy = re.sub(r'\s+AND\s+Epoch:\d+', '', base_policy, flags=re.IGNORECASE).strip()
            if cleaned_policy.startswith("(") and cleaned_policy.endswith(")"):
                new_policy = f"{cleaned_policy} AND Epoch:{target_epoch}"
            else:
                new_policy = f"({cleaned_policy}) AND Epoch:{target_epoch}"

            # Step 2: Re-encrypt via HybridCipher (Preserving exact KEM/DEM architecture)
            pkg = self.hybrid.encrypt_document(self.pk, decrypted_bytes, new_policy)

            # Step 3: Filesystem staged replacement
            new_uuid = uuid.uuid4().hex
            final_stored_filename = f"{new_uuid}.enc"
            staged_filename = f"{new_uuid}.staged.enc"

            staged_path = os.path.join(config.ENCRYPTED_DIR, staged_filename)
            final_path = os.path.join(config.ENCRYPTED_DIR, final_stored_filename)
            old_path = os.path.join(config.ENCRYPTED_DIR, old_stored_filename)

            raw_aes_ct = base64.b64decode(pkg["aes_ciphertext"].encode('ascii'))
            with open(staged_path, "wb") as f:
                f.write(raw_aes_ct)

            # Verify staged file exists and is non-empty
            if not os.path.exists(staged_path) or os.path.getsize(staged_path) == 0:
                if os.path.exists(staged_path):
                    os.unlink(staged_path)
                raise RuntimeError("Staged ciphertext verification failed: file empty or missing.")

            # Rename staged file to its final UUID filename before DB commit (Clarification 1)
            os.rename(staged_path, final_path)

            # Step 4: Transactional Database Update
            try:
                conn.execute("BEGIN TRANSACTION")
                conn.execute(
                    """
                    UPDATE documents SET
                        stored_filename = ?,
                        file_size = ?,
                        access_policy = ?,
                        formatted_policy = ?,
                        cpabe_ciphertext = ?,
                        aes_nonce = ?,
                        aes_tag = ?,
                        epoch = ?
                    WHERE id = ?
                    """,
                    (
                        final_stored_filename,
                        len(decrypted_bytes),
                        new_policy,
                        pkg["policy"],
                        pkg["cpabe_ciphertext"],
                        pkg["nonce"],
                        pkg["tag"],
                        target_epoch,
                        doc_id
                    )
                )
                conn.commit()
            except Exception as db_err:
                conn.rollback()
                # Clean up new final file if DB failed
                if os.path.exists(final_path):
                    try:
                        os.unlink(final_path)
                    except OSError:
                        pass
                raise RuntimeError(f"Database update failed during re-encryption: {db_err}") from db_err

            # Step 5: Only after commit success, delete old ciphertext file (Clarification 1)
            if os.path.exists(old_path) and old_path != final_path:
                try:
                    os.unlink(old_path)
                except OSError:
                    pass

            # Step 6: Log audit
            self.log_audit(
                user_id=reencryptor_user_id,
                username=reencryptor_username,
                action="DOC_RE_ENCRYPTED",
                status="SUCCESS",
                details=f"Re-encrypted '{original_filename}' (id={doc_id}) to Epoch {target_epoch} under policy: {new_policy}",
                ip_address=ip_address
            )

            return {
                "id": doc_id,
                "original_filename": original_filename,
                "file_size": len(decrypted_bytes),
                "access_policy": new_policy,
                "formatted_policy": pkg["policy"],
                "stored_filename": final_stored_filename,
                "epoch": target_epoch
            }
        finally:
            conn.close()

    def reencrypt_all_documents(
        self,
        reencryptor_user_id: int,
        reencryptor_username: str,
        reencryptor_passphrase: str,
        target_epoch: int = None,
        ip_address: str = None
    ) -> Dict[str, Any]:
        """
        Multi-Stage Epoch Rotation Lifecycle Execution:
        Re-encrypts all eligible documents to the target epoch.
        Enforces Clarification 3: Reports PARTIAL_FAILURE if even one document fails.
        Only marks rotation COMPLETED if 100% succeed.
        """
        if target_epoch is None:
            target_epoch = self.get_current_epoch()

        conn = get_db()
        docs = conn.execute(
            "SELECT id, original_filename, epoch FROM documents WHERE epoch != ?", (target_epoch,)
        ).fetchall()
        conn.close()

        total = len(docs)
        succeeded = []
        failed = []

        # Update lifecycle state to RE_ENCRYPTING
        conn = get_db()
        conn.execute("UPDATE system_epochs SET status = 'RE_ENCRYPTING' WHERE epoch_number = ?", (target_epoch,))
        conn.commit()
        conn.close()

        for d in docs:
            doc_id = d["id"]
            orig_name = d["original_filename"]
            try:
                res = self.reencrypt_document(
                    doc_id=doc_id,
                    reencryptor_user_id=reencryptor_user_id,
                    reencryptor_username=reencryptor_username,
                    reencryptor_passphrase=reencryptor_passphrase,
                    target_epoch=target_epoch,
                    ip_address=ip_address
                )
                succeeded.append(res)
            except Exception as e:
                failed.append({
                    "doc_id": doc_id,
                    "filename": orig_name,
                    "error": str(e)
                })

        # Determine lifecycle status (Clarification 3)
        final_status = "COMPLETED" if len(failed) == 0 else "PARTIAL_FAILURE"

        conn = get_db()
        conn.execute("UPDATE system_epochs SET status = ? WHERE epoch_number = ?", (final_status, target_epoch))
        conn.commit()
        conn.close()

        return {
            "epoch": target_epoch,
            "status": final_status,
            "total_documents": total,
            "reencrypted_count": len(succeeded),
            "failed_count": len(failed),
            "succeeded": succeeded,
            "failures": failed
        }

    # ------------------------------------------------------------------ #
    # Startup Crash Recovery (Clarification 1)                           #
    # ------------------------------------------------------------------ #
    def cleanup_unreferenced_files(self) -> int:
        """
        Crash Recovery Routine:
        Scans storage/encrypted/ for:
        1. Any *.staged.enc files (aborted staged writes).
        2. Any unreferenced *.enc files not present in the documents database.
        Safely deletes them to maintain filesystem consistency.
        """
        if not os.path.exists(config.ENCRYPTED_DIR):
            return 0

        conn = get_db()
        try:
            active_files = set(
                row[0] for row in conn.execute("SELECT stored_filename FROM documents").fetchall()
            )
        finally:
            conn.close()

        purged_count = 0
        for fname in os.listdir(config.ENCRYPTED_DIR):
            fpath = os.path.join(config.ENCRYPTED_DIR, fname)
            if not os.path.isfile(fpath):
                continue

            # 1. Purge staged files
            if ".staged." in fname:
                try:
                    os.unlink(fpath)
                    purged_count += 1
                except OSError:
                    pass
            # 2. Purge unreferenced .enc files
            elif fname.endswith(".enc") and fname not in active_files:
                try:
                    os.unlink(fpath)
                    purged_count += 1
                except OSError:
                    pass

        return purged_count

    # ------------------------------------------------------------------ #
    # Genuine Cryptographic Revocation Verification (No Key Exposure)   #
    # ------------------------------------------------------------------ #
    def verify_revocation_cryptography(
        self,
        doc_id: int,
        test_user_id: int,
        test_user_passphrase: str,
        old_key_version: Optional[int] = None,
        new_key_version: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Executes genuine Charm-Crypto BSW07 pairing tests to verify that:
        - Old key (prior epoch) fails mathematically against the re-encrypted ciphertext.
        - New key (current epoch) succeeds mathematically.
        Zero key material or secret elements are ever exposed or returned.
        """
        conn = get_db()
        try:
            # 1. Verify user existence and authenticate passphrase against stored hash
            user = conn.execute("SELECT * FROM users WHERE id = ?", (test_user_id,)).fetchone()
            if not user:
                raise ValueError(f"User #{test_user_id} not found.")

            if not verify_password(test_user_passphrase, user["password_hash"]):
                raise ValueError("Invalid passphrase: password does not match user account.")

            # 2. Verify document existence
            doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
            if not doc:
                raise ValueError("Document not found.")

            # 3. Dynamic key version lookup: resolve active key and prior superseded key if not specified
            if new_key_version is None:
                active_k = conn.execute(
                    "SELECT key_version FROM user_keys WHERE user_id = ? AND is_active = 1",
                    (test_user_id,)
                ).fetchone()
                if active_k:
                    new_key_version = active_k["key_version"]
                else:
                    max_k = conn.execute(
                        "SELECT MAX(key_version) AS max_v FROM user_keys WHERE user_id = ?",
                        (test_user_id,)
                    ).fetchone()
                    if max_k and max_k["max_v"]:
                        new_key_version = max_k["max_v"]
                    else:
                        raise ValueError(f"No cryptographic keys found for user '{user['username']}'.")

            if old_key_version is None:
                old_k = conn.execute(
                    "SELECT key_version FROM user_keys WHERE user_id = ? AND key_version < ? ORDER BY key_version ASC LIMIT 1",
                    (test_user_id, new_key_version)
                ).fetchone()
                if old_k:
                    old_key_version = old_k["key_version"]
                else:
                    old_key_version = 1

            # Fetch old key
            old_k_row = conn.execute(
                "SELECT * FROM user_keys WHERE user_id = ? AND key_version = ?",
                (test_user_id, old_key_version)
            ).fetchone()
            if not old_k_row:
                raise ValueError(f"Old key version {old_key_version} not found for user {test_user_id}")

            # Fetch new key
            new_k_row = conn.execute(
                "SELECT * FROM user_keys WHERE user_id = ? AND key_version = ?",
                (test_user_id, new_key_version)
            ).fetchone()
            if not new_k_row:
                raise ValueError(f"New key version {new_key_version} not found for user {test_user_id}")

            # Read AES ciphertext from disk
            disk_path = os.path.join(config.ENCRYPTED_DIR, doc["stored_filename"])
            with open(disk_path, "rb") as f:
                raw_aes_ct = f.read()

            encrypted_pkg = {
                "cpabe_ciphertext": doc["cpabe_ciphertext"],
                "aes_ciphertext": base64.b64encode(raw_aes_ct).decode('ascii'),
                "nonce": doc["aes_nonce"],
                "tag": doc["aes_tag"]
            }

            # Decrypt old private key into transient memory
            try:
                old_sk = self.key_store.decrypt_user_key(old_k_row["encrypted_sk"], test_user_passphrase)
            except ValueError as e:
                raise ValueError(f"Old key (v{old_key_version}) decryption failed: invalid passphrase or corrupted envelope.") from e
            old_key_attrs = json.loads(old_k_row["bound_attributes"])

            # Test A: Old key against document's current ciphertext
            old_key_success = False
            old_key_reason = None
            try:
                self.hybrid.decrypt_document(self.pk, old_sk, encrypted_pkg)
                old_key_success = True
            except AccessDeniedError as e:
                old_key_success = False
                old_key_reason = str(e)

            # Decrypt new private key into transient memory
            try:
                new_sk = self.key_store.decrypt_user_key(new_k_row["encrypted_sk"], test_user_passphrase)
            except ValueError as e:
                raise ValueError(f"New key (v{new_key_version}) decryption failed: invalid passphrase or corrupted envelope.") from e
            new_key_attrs = json.loads(new_k_row["bound_attributes"])

            # Test B: New key against document's current ciphertext
            new_key_success = False
            new_key_reason = None
            try:
                self.hybrid.decrypt_document(self.pk, new_sk, encrypted_pkg)
                new_key_success = True
            except AccessDeniedError as e:
                new_key_success = False
                new_key_reason = str(e)

            return {
                "document_id": doc_id,
                "original_filename": doc["original_filename"],
                "document_epoch": doc["epoch"],
                "access_policy": doc["access_policy"],
                "old_key_test": {
                    "version": old_key_version,
                    "bound_attributes": old_key_attrs,
                    "decryption_succeeded": old_key_success,
                    "pairing_status": "GRANTED" if old_key_success else "DENIED_BY_PAIRING",
                    "reason": old_key_reason
                },
                "new_key_test": {
                    "version": new_key_version,
                    "bound_attributes": new_key_attrs,
                    "decryption_succeeded": new_key_success,
                    "pairing_status": "GRANTED" if new_key_success else "DENIED_BY_PAIRING",
                    "reason": new_key_reason
                },
                "cryptographic_revocation_effective": (not old_key_success) and new_key_success
            }
        finally:
            conn.close()
