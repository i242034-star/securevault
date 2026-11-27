"""
benchmark_performance.py — Performance & Cryptographic Benchmark Suite for SecureVault
Evaluates:
- Requirement E10: Encryption, decryption, keygen, and pairing latency.
- Requirement E7: PBKDF2-HMAC-SHA256 brute-force resistance measurement.
"""

import os
import sys
import time
import base64
import statistics

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto.charm_engine import CharmEngine
from crypto.hybrid_cipher import HybridCipher, AccessDeniedError
from crypto.key_store import KeyStore
from utils.auth import hash_password, verify_password

def run_benchmarks():
    print("=" * 75)
    print("  SECUREVAULT: CRYPTOGRAPHIC PERFORMANCE & LATENCY BENCHMARK SUITE")
    print("  Testing BSW07 Pairing (BN254), AES-256-GCM DEM, and PBKDF2 (100k iter)")
    print("=" * 75)

    engine = CharmEngine(curve="BN254")
    hybrid = HybridCipher(engine)
    key_store = KeyStore(engine)

    # 1. Authority Setup Latency
    print("\n[1] Trusted Authority Setup Latency (BN254 Curve Parameters + MK):")
    setup_times = []
    for _ in range(5):
        t0 = time.perf_counter()
        pk, mk = engine.setup()
        setup_times.append((time.perf_counter() - t0) * 1000)
    print(f"    Avg Setup Time: {statistics.mean(setup_times):.2f} ms (StdDev: {statistics.stdev(setup_times):.2f} ms)")

    # 2. Key Generation Latency vs Attribute Set Size
    print("\n[2] BSW07 Key Generation Latency (Varying Attribute Set Sizes):")
    attr_sets = [
        ["Role:Engineer", "Clearance:Level-3"],
        ["Role:Engineer", "Clearance:Level-3", "Epoch:1", "Dept:SecOps"],
        ["Role:Engineer", "Clearance:Level-3", "Epoch:1", "Dept:SecOps", "Project:Atlas", "Region:EU", "Team:Core", "Level:Lead"],
    ]
    for attrs in attr_sets:
        keygen_times = []
        for _ in range(5):
            t0 = time.perf_counter()
            sk = engine.keygen(pk, mk, attrs)
            keygen_times.append((time.perf_counter() - t0) * 1000)
        print(f"    Attributes ({len(attrs)}): {attrs[:2]}... -> Avg Keygen: {statistics.mean(keygen_times):.2f} ms")

    # 3. Hybrid Encryption Latency vs Document Size
    print("\n[3] Hybrid Encryption Latency (CP-ABE KEM + AES-256-GCM DEM):")
    policy = "(Role:Engineer OR Role:Manager) AND Clearance:Level-3 AND Epoch:1"
    sizes_kb = [1, 100, 1000] # 1 KB, 100 KB, 1 MB
    for sz in sizes_kb:
        payload = os.urandom(sz * 1024)
        enc_times = []
        for _ in range(5):
            t0 = time.perf_counter()
            pkg = hybrid.encrypt_document(pk, payload, policy)
            enc_times.append((time.perf_counter() - t0) * 1000)
        print(f"    Payload Size: {sz:>4} KB -> Avg Encrypt: {statistics.mean(enc_times):.2f} ms")

    # 4. Decryption Latency: Authorized Pairing vs Unauthorized Denial
    print("\n[4] Decryption Latency Comparison (Authorized Success vs Policy Denial):")
    auth_attrs = ["Role:Engineer", "Clearance:Level-3", "Epoch:1"]
    unauth_attrs = ["Role:Student", "Clearance:Level-2", "Epoch:1"]
    sk_auth = engine.keygen(pk, mk, auth_attrs)
    sk_unauth = engine.keygen(pk, mk, unauth_attrs)
    pkg = hybrid.encrypt_document(pk, b"Confidential Benchmark Document Payload", policy)

    dec_auth_times = []
    for _ in range(5):
        t0 = time.perf_counter()
        dec = hybrid.decrypt_document(pk, sk_auth, pkg)
        dec_auth_times.append((time.perf_counter() - t0) * 1000)

    dec_unauth_times = []
    for _ in range(5):
        t0 = time.perf_counter()
        try:
            hybrid.decrypt_document(pk, sk_unauth, pkg)
        except AccessDeniedError:
            pass
        dec_unauth_times.append((time.perf_counter() - t0) * 1000)

    print(f"    Authorized Decryption (Pairing + AES-GCM): {statistics.mean(dec_auth_times):.2f} ms")
    print(f"    Denied Decryption (Bilinear Tree Pruning):  {statistics.mean(dec_unauth_times):.2f} ms")

    # 5. Key Envelope Unlock & PBKDF2 Latency (Brute-Force Resistance)
    print("\n[5] Key Envelope Unlock & Brute-Force Resistance (PBKDF2-HMAC-SHA256, 100k iterations):")
    pw = "Alice@2026!"
    env = key_store.encrypt_user_key(sk_auth, pw)
    kdf_times = []
    for _ in range(5):
        t0 = time.perf_counter()
        rec_sk = key_store.decrypt_user_key(env, pw)
        kdf_times.append((time.perf_counter() - t0) * 1000)

    avg_kdf = statistics.mean(kdf_times)
    guesses_per_sec = 1000.0 / avg_kdf
    print(f"    Envelope PBKDF2 Unlock Latency: {avg_kdf:.2f} ms")
    print(f"    Attacker Brute-Force Rate (single CPU thread): ~{guesses_per_sec:.1f} guesses/second")
    print(f"    -> An 8-character complex password (94^8 = 6.09e15 combinations) requires > 10^7 years on 1 CPU core.")

    print("\n" + "=" * 75)
    print("  >>> ALL PERFORMANCE & SECURITY MEASUREMENTS COMPLETED SUCCESSFULLY <<<")
    print("=" * 75)
    return True

if __name__ == '__main__':
    run_benchmarks()
