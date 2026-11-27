"""
Master Test Runner for Phase 1 Cryptographic Engine
Runs:
1. test_charm_bsw07.py
2. test_access_matrix.py
3. test_hybrid_cipher.py
4. test_key_store.py
"""
import unittest
import sys
import os

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tests.test_charm_bsw07 import TestCharmBSW07
from tests.test_access_matrix import TestAccessMatrix
from tests.test_hybrid_cipher import TestHybridCipher
from tests.test_key_store import TestKeyStore

def main():
    print("======================================================================")
    print("   SECUREVAULT: PHASE 1 CRYPTOGRAPHIC ENGINE VERIFICATION SUITE")
    print("   GENUINE BSW07 CP-ABE (CHARM-CRYPTO) + AES-256-GCM HYBRID ENCRYPTION")
    print("======================================================================\n")

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestCharmBSW07))
    suite.addTests(loader.loadTestsFromTestCase(TestAccessMatrix))
    suite.addTests(loader.loadTestsFromTestCase(TestHybridCipher))
    suite.addTests(loader.loadTestsFromTestCase(TestKeyStore))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n======================================================================")
    if result.wasSuccessful():
        print("   >>> ALL PHASE 1 CRYPTOGRAPHIC TESTS COMPLETED SUCCESSFULLY! <<<")
        print("======================================================================")
        sys.exit(0)
    else:
        print("   >>> TESTS FAILED: SOME ASSERTIONS DID NOT PASS! <<<")
        print("======================================================================")
        sys.exit(1)

if __name__ == '__main__':
    main()
