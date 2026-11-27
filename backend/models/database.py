"""
Database Management Module for SQLite
Provides schema initialization, connection context, transactional queries,
and idempotent Phase 4 migrations for dynamic attributes and epoch-based revocation.
"""
import sqlite3
import os
import sys

# Add parent directory for config
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import config


def get_db(db_path: str = None) -> sqlite3.Connection:
    """
    Get a configured SQLite database connection.
    Enables foreign keys and returns dictionary-like sqlite3.Row objects.
    """
    path = db_path if db_path is not None else config.DATABASE_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: str = None) -> None:
    """
    Create all required database tables for SecureVault and apply Phase 4 schema migrations.
    """
    conn = get_db(db_path)
    cursor = conn.cursor()

    cursor.executescript("""
    -- Users Table
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        system_role TEXT NOT NULL DEFAULT 'user', -- 'admin' or 'user'
        role_attr TEXT NOT NULL,                 -- 'Role:Engineer', 'Role:Manager', etc.
        clearance_attr TEXT NOT NULL,            -- 'Clearance:Level-1', 'Clearance:Level-2', 'Clearance:Level-3'
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- User Cryptographic Keys Table (Encrypted at rest)
    CREATE TABLE IF NOT EXISTS user_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        key_version INTEGER NOT NULL DEFAULT 1,
        bound_attributes TEXT NOT NULL,          -- JSON list of attributes embedded in key
        encrypted_sk TEXT NOT NULL,              -- AES-256-GCM envelope JSON (never plaintext)
        is_active INTEGER NOT NULL DEFAULT 1,    -- 1 if current active key, 0 if superseded
        issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Documents Table
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uploader_id INTEGER NOT NULL REFERENCES users(id),
        original_filename TEXT NOT NULL,
        stored_filename TEXT UNIQUE NOT NULL,    -- UUID filename on disk (.enc)
        file_size INTEGER NOT NULL,
        access_policy TEXT NOT NULL,             -- User-friendly policy string
        formatted_policy TEXT NOT NULL,          -- Charm AST-compatible policy string
        cpabe_ciphertext TEXT NOT NULL,          -- Base64 serialized CP-ABE ciphertext
        aes_nonce TEXT NOT NULL,                 -- Base64 12-byte IV
        aes_tag TEXT NOT NULL,                   -- Base64 16-byte authentication tag
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Security Audit Logs Table (Tamper-evident cryptographic hash chain)
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sequence_number INTEGER,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        username TEXT NOT NULL,
        action TEXT NOT NULL,                    -- 'LOGIN', 'KEY_ISSUANCE', 'DOC_UPLOAD', 'DECRYPT_SUCCESS', 'DECRYPT_DENIED', 'ATTRIBUTE_CHANGE', 'EPOCH_ADVANCED', 'DOC_RE_ENCRYPTED'
        status TEXT NOT NULL,                    -- 'SUCCESS', 'DENIED', 'FAILED'
        details TEXT,
        ip_address TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        previous_hash TEXT,
        record_hash TEXT
    );

    -- System Epochs Table (Phase 4: Epoch-based Revocation Lifecycle)
    CREATE TABLE IF NOT EXISTS system_epochs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        epoch_number INTEGER NOT NULL UNIQUE,
        reason TEXT NOT NULL,
        initiated_by TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'DECLARED', -- 'DECLARED', 'RE_ENCRYPTING', 'KEY_UPDATING', 'COMPLETED', 'PARTIAL_FAILURE'
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Create indexes for performance and fast lookups
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    CREATE INDEX IF NOT EXISTS idx_user_keys_user_id ON user_keys(user_id);
    CREATE INDEX IF NOT EXISTS idx_documents_uploader ON documents(uploader_id);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_system_epochs_number ON system_epochs(epoch_number);
    """)

    # ------------------------------------------------------------------ #
    # Phase 4 Schema Migrations (Idempotent column additions)            #
    # ------------------------------------------------------------------ #
    user_columns = [row[1] for row in cursor.execute("PRAGMA table_info(users)").fetchall()]
    if "custom_attributes" not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN custom_attributes TEXT NOT NULL DEFAULT '[]'")
    if "pending_key_reissue" not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN pending_key_reissue INTEGER NOT NULL DEFAULT 0")

    doc_columns = [row[1] for row in cursor.execute("PRAGMA table_info(documents)").fetchall()]
    if "epoch" not in doc_columns:
        cursor.execute("ALTER TABLE documents ADD COLUMN epoch INTEGER NOT NULL DEFAULT 0")

    # Seed initial Epoch 1 if table is empty
    epoch_count = cursor.execute("SELECT COUNT(*) FROM system_epochs").fetchone()[0]
    if epoch_count == 0:
        cursor.execute(
            "INSERT INTO system_epochs (epoch_number, reason, initiated_by, status) VALUES (1, 'Initial System Epoch', 'system', 'COMPLETED')"
        )

    # ------------------------------------------------------------------ #
    # Cryptographic Audit Log Hash-Chain Migrations                      #
    # ------------------------------------------------------------------ #
    audit_columns = [row[1] for row in cursor.execute("PRAGMA table_info(audit_logs)").fetchall()]
    if "sequence_number" not in audit_columns:
        cursor.execute("ALTER TABLE audit_logs ADD COLUMN sequence_number INTEGER")
    if "previous_hash" not in audit_columns:
        cursor.execute("ALTER TABLE audit_logs ADD COLUMN previous_hash TEXT")
    if "record_hash" not in audit_columns:
        cursor.execute("ALTER TABLE audit_logs ADD COLUMN record_hash TEXT")

    # Migrate any legacy audit records into the hash chain
    from crypto.audit_chain import migrate_legacy_records
    migrate_legacy_records(conn)

    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_logs_sequence ON audit_logs(sequence_number);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_record_hash ON audit_logs(record_hash);")

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Database schema initialized successfully at:", config.DATABASE_PATH)
