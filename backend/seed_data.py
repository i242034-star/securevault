"""
seed_data.py — Populate the database with test users for SecureVault.

Run with:
    python3 seed_data.py

Creates five users:
  admin   | Admin@2026!  | admin | Role:Engineer + Clearance:Level-3
  alice   | Alice@2026!  | user  | Role:Engineer + Clearance:Level-3  → EXPECT: decryption SUCCESS
  bob     | Bob@2026!    | user  | Role:Student  + Clearance:Level-3  → EXPECT: decryption DENIED
  charlie | Charlie@2026!| user  | Role:Manager  + Clearance:Level-3  → EXPECT: decryption SUCCESS
  david   | David@2026!  | user  | Role:Engineer + Clearance:Level-2  → EXPECT: decryption DENIED
"""

import os
import sys

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from models.database import init_db, get_db
from utils.auth import hash_password
from crypto.service import CryptoService


USERS = [
    {
        "username": "admin",
        "password": "Admin@2026!",
        "system_role": "admin",
        "role_attr": "Role:Engineer",
        "clearance_attr": "Clearance:Level-3",
    },
    {
        "username": "alice",
        "password": "Alice@2026!",
        "system_role": "user",
        "role_attr": "Role:Engineer",
        "clearance_attr": "Clearance:Level-3",
    },
    {
        "username": "bob",
        "password": "Bob@2026!",
        "system_role": "user",
        "role_attr": "Role:Student",
        "clearance_attr": "Clearance:Level-3",
    },
    {
        "username": "charlie",
        "password": "Charlie@2026!",
        "system_role": "user",
        "role_attr": "Role:Manager",
        "clearance_attr": "Clearance:Level-3",
    },
    {
        "username": "david",
        "password": "David@2026!",
        "system_role": "user",
        "role_attr": "Role:Engineer",
        "clearance_attr": "Clearance:Level-2",
    },
]


SAMPLE_PDF_PATH = os.path.join(BACKEND_DIR, "tests", "sample_confidential.pdf")
SAMPLE_DOC_NAME = "Project_Atlas_Confidential.pdf"

# Fallback minimal PDF if the sample file isn't shipped with the build
_MINIMAL_PDF = (
    b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n"
    b"xref\n0 4\n0000000000 65535 f\r\n0000000009 00000 n\r\n"
    b"0000000058 00000 n\r\n0000000115 00000 n\r\n"
    b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF\n"
)


def seed_sample_document(svc) -> bool:
    """Encrypt one sample PDF under the core project policy if the vault is empty."""
    import config
    db = get_db()
    try:
        if db.execute("SELECT COUNT(*) FROM documents").fetchone()[0] > 0:
            return False
        admin = db.execute("SELECT id, username FROM users WHERE system_role = 'admin' ORDER BY id LIMIT 1").fetchone()
        if not admin:
            return False
    finally:
        db.close()

    if os.path.exists(SAMPLE_PDF_PATH):
        with open(SAMPLE_PDF_PATH, "rb") as f:
            pdf_bytes = f.read()
    else:
        pdf_bytes = _MINIMAL_PDF

    svc.encrypt_and_store_document(
        uploader_id=admin["id"],
        uploader_username=admin["username"],
        original_filename=SAMPLE_DOC_NAME,
        file_bytes=pdf_bytes,
        policy_str=config.DEFAULT_CORE_POLICY,
    )
    print(f"[+] Sample document '{SAMPLE_DOC_NAME}' encrypted under: {config.DEFAULT_CORE_POLICY}")
    return True


def seed_if_empty() -> bool:
    """Seed demo data only when no users exist. Returns True if seeding ran."""
    init_db()
    db = get_db()
    try:
        has_users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0
    finally:
        db.close()
    if has_users:
        return False
    seed()
    return True


def seed():
    # Initialise the database schema
    init_db()
    db = get_db()

    # Boot the crypto authority (creates or loads MK+PK)
    svc = CryptoService.get_instance()
    print("[*] CryptoService ready.")

    for u in USERS:
        username = u["username"]
        # Check if user already exists
        existing = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()

        if existing:
            print(f"[~] User '{username}' already exists — skipping creation.")
            user_id = existing["id"]
        else:
            pw_hash = hash_password(u["password"])
            cursor = db.execute(
                """
                INSERT INTO users (username, password_hash, system_role, role_attr, clearance_attr)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, pw_hash, u["system_role"], u["role_attr"], u["clearance_attr"]),
            )
            db.commit()
            user_id = cursor.lastrowid
            print(f"[+] Created user '{username}' (id={user_id}).")

        # Determine whether a CP-ABE private key already exists for this user
        existing_key = db.execute(
            "SELECT id FROM user_keys WHERE user_id = ? AND is_active = 1", (user_id,)
        ).fetchone()

        if existing_key:
            print(f"[~] Active key for '{username}' already exists — skipping key issuance.")
        else:
            try:
                svc.issue_user_key(
                    user_id=user_id,
                    username=username,
                    attributes=[u["role_attr"], u["clearance_attr"]],
                    user_passphrase=u["password"],
                )
                print(
                    f"[+] CP-ABE key issued for '{username}' "
                    f"[{u['role_attr']}, {u['clearance_attr']}]."
                )
            except Exception as exc:
                print(f"[!] Failed to issue key for '{username}': {exc}")

    seed_sample_document(svc)

    print("\n[OK] Seed complete.")
    print("\nUser summary:")
    rows = db.execute(
        "SELECT u.id, u.username, u.system_role, u.role_attr, u.clearance_attr, "
        "       (SELECT COUNT(*) FROM user_keys k WHERE k.user_id = u.id AND k.is_active=1) AS has_key "
        "FROM users u ORDER BY u.id"
    ).fetchall()
    print(f"  {'ID':<4} {'Username':<10} {'Role':<8} {'Attr (Role)':<20} {'Attr (Clearance)':<22} Key")
    print("  " + "-" * 72)
    for r in rows:
        print(
            f"  {r['id']:<4} {r['username']:<10} {r['system_role']:<8} "
            f"{r['role_attr']:<20} {r['clearance_attr']:<22} {'YES' if r['has_key'] else 'NO'}"
        )


if __name__ == "__main__":
    seed()
