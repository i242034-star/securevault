"""
verify_revocation_demo.py — Cryptographic Revocation Scenario Verification
Demonstrates exact 9-step scenario plus revoked and authorized user tests.
"""
import sys
import os
import tempfile

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto.charm_engine import CharmEngine
from crypto.hybrid_cipher import HybridCipher, AccessDeniedError, TamperError
from crypto.key_store import KeyStore

def run_verification():
    print("================================================================================")
    print("   SECUREVAULT: CRYPTOGRAPHIC REVOCATION LIVE VERIFICATION AUDIT")
    print("================================================================================\n")
    
    engine = CharmEngine(curve="BN254")
    hybrid = HybridCipher(engine)
    key_store = KeyStore(engine)

    print("[*] Setting up Trusted Authority (BSW07 on BN254 curve)...")
    pk, mk = engine.setup()
    print("    -> Public parameters generated.")
    print("    -> Master secret key generated.\n")

    # Sample PDF document
    test_pdf_content = b"%PDF-1.4\n%SecureVault Cryptographic Audit Verification Document\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\nxref\n0 4\n0000000000 65535 f\r\n0000000009 00000 n\r\n0000000058 00000 n\r\n0000000115 00000 n\r\ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF\n"

    # Step 1: Alice has Engineer and Level-3 attributes with Epoch-1
    print("--- STEP 1: Assign attributes to Alice (Epoch 1) ---")
    alice_epoch1_attrs = ["Role:Engineer", "Clearance:Level-3", "Epoch:1"]
    alice_sk_epoch1 = engine.keygen(pk, mk, alice_epoch1_attrs)
    print(f"    Alice Epoch-1 attributes: {alice_epoch1_attrs}")
    print("    Private key v1 successfully generated.\n")

    # Step 2: Encrypt a document under policy requiring Engineer, Level-3, and Epoch-1
    policy_epoch1 = "(Role:Engineer OR Role:Manager) AND Clearance:Level-3 AND Epoch:1"
    print("--- STEP 2: Encrypt document under Epoch 1 policy ---")
    print(f"    Access Policy: {policy_epoch1}")
    pkg_epoch1 = hybrid.encrypt_document(pk, test_pdf_content, policy_epoch1)
    print("    -> Generated KEM secret (GT element) encapsulated under CP-ABE policy tree.")
    print("    -> Encrypted document payload with AES-256-GCM.")
    print(f"    -> AES ciphertext length: {len(pkg_epoch1['aes_ciphertext'])} base64 chars.\n")

    # Step 3: Verify Alice can decrypt it
    print("--- STEP 3: Verify Alice decrypts document using Epoch 1 key ---")
    try:
        decrypted_p1 = hybrid.decrypt_document(pk, alice_sk_epoch1, pkg_epoch1)
        assert decrypted_p1 == test_pdf_content
        print("    [SUCCESS] Alice decrypted document successfully! Recovered exact PDF bytes.")
    except Exception as e:
        print(f"    [FAILED] Alice decryption failed: {e}")
        return False
    print()

    # Step 4: Advance the system to Epoch-2
    print("--- STEP 4: Advance system to Epoch 2 ---")
    current_epoch = 2
    print(f"    Current System Epoch transitioned: 1 -> {current_epoch}\n")

    # Step 5: Re-encrypt the document under the updated policy (Epoch-2)
    policy_epoch2 = "(Role:Engineer OR Role:Manager) AND Clearance:Level-3 AND Epoch:2"
    print("--- STEP 5: Re-encrypt document under Epoch 2 policy ---")
    print(f"    Updated Access Policy: {policy_epoch2}")
    pkg_epoch2 = hybrid.encrypt_document(pk, test_pdf_content, policy_epoch2)
    print("    -> Re-encrypted with fresh KEM secret under Epoch 2 policy tree.\n")

    # Step 6 & 7: Attempt decryption using Alice's old Epoch-1 private key & verify it fails
    print("--- STEPS 6 & 7: Attempt decryption with Alice's OLD Epoch-1 private key ---")
    try:
        hybrid.decrypt_document(pk, alice_sk_epoch1, pkg_epoch2)
        print("    [CRITICAL FAILURE] Old key was able to decrypt Epoch 2 ciphertext!")
        return False
    except AccessDeniedError as e:
        print("    [SUCCESS - MATHEMATICAL REVOCATION VERIFIED]")
        print(f"    Decryption correctly failed with AccessDeniedError: {e}")
        print("    BSW07 bilinear pairing reconstruction failed because Epoch:1 does NOT satisfy Epoch:2.")
    print()

    # Step 8: Issue or allow Alice to claim an updated Epoch-2 key
    print("--- STEP 8: Issue/Claim updated Epoch-2 key for Alice ---")
    alice_epoch2_attrs = ["Role:Engineer", "Clearance:Level-3", "Epoch:2"]
    alice_sk_epoch2 = engine.keygen(pk, mk, alice_epoch2_attrs)
    print(f"    Alice Epoch-2 attributes: {alice_epoch2_attrs}")
    print("    Private key v2 successfully generated/claimed.\n")

    # Step 9: Verify that the updated key succeeds
    print("--- STEP 9: Verify updated Epoch-2 key succeeds on Epoch-2 ciphertext ---")
    try:
        decrypted_p2 = hybrid.decrypt_document(pk, alice_sk_epoch2, pkg_epoch2)
        assert decrypted_p2 == test_pdf_content
        print("    [SUCCESS] Alice decrypted re-encrypted document using Epoch-2 key!")
        print("    Recovered exact original PDF payload.\n")
    except Exception as e:
        print(f"    [FAILED] Alice Epoch-2 key failed: {e}")
        return False

    # Additional Verification: Revoked user & Authorized user
    print("--- ADDITIONAL TEST 1: Revoked / Unauthorized User (Bob - Student) in Epoch 2 ---")
    bob_epoch2_attrs = ["Role:Student", "Clearance:Level-3", "Epoch:2"]
    bob_sk_epoch2 = engine.keygen(pk, mk, bob_epoch2_attrs)
    print(f"    Bob has Epoch:2 but Role:Student: {bob_epoch2_attrs}")
    try:
        hybrid.decrypt_document(pk, bob_sk_epoch2, pkg_epoch2)
        print("    [CRITICAL FAILURE] Unauthorized user Bob decrypted document!")
        return False
    except AccessDeniedError as e:
        print("    [SUCCESS] Bob mathematically denied (Role:Student does not satisfy policy).")
    print()

    print("--- ADDITIONAL TEST 2: Authorized User (Charlie - Manager) in Epoch 2 ---")
    charlie_epoch2_attrs = ["Role:Manager", "Clearance:Level-3", "Epoch:2"]
    charlie_sk_epoch2 = engine.keygen(pk, mk, charlie_epoch2_attrs)
    print(f"    Charlie attributes: {charlie_epoch2_attrs}")
    try:
        decrypted_charlie = hybrid.decrypt_document(pk, charlie_sk_epoch2, pkg_epoch2)
        assert decrypted_charlie == test_pdf_content
        print("    [SUCCESS] Authorized user Charlie successfully decrypted Epoch 2 document.")
    except Exception as e:
        print(f"    [FAILED] Charlie decryption failed: {e}")
        return False
    print()

    print("================================================================================")
    print("   >>> CRYPTOGRAPHIC REVOCATION SCENARIO 100% VERIFIED <<<")
    print("================================================================================")
    return True

if __name__ == '__main__':
    success = run_verification()
    sys.exit(0 if success else 1)
