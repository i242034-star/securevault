"""
Attack Simulator ("Attack Lab")
================================
Runs real, empirical attacks against the SecureVault cryptographic stack and
reports whether each countermeasure held.

Every simulation runs inside an isolated *sandbox authority*: a fresh BSW07
setup (its own PK/MK) created for that run. Nothing here touches the
production master key, real user keys or stored documents, and no key
material is ever returned to the caller — only verdicts and measurements.

Attacks
-------
  collusion          Two under-privileged users merge their key components.
  policy_tampering   An attacker rewrites the ciphertext's access policy.
  ciphertext_tamper  Bit-flip on the AES-256-GCM payload (DEM integrity).
  revoked_key        Replay a pre-revocation key after an epoch rotation.
  brute_force        Online password guessing + offline cracking cost.
  timing_leak        Username enumeration through login response timing.
"""
import base64
import hashlib
import os
import statistics
import time
from typing import Any, Callable, Dict, List

from .charm_engine import CharmEngine
from .hybrid_cipher import HybridCipher, AccessDeniedError, TamperError

CORE_POLICY = "(Role:Engineer OR Role:Manager) AND Clearance:Level-3"


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 2)


class AttackSimulator:
    def __init__(self, engine: CharmEngine = None):
        self.engine = engine or CharmEngine(curve="BN254")
        self.hybrid = HybridCipher(self.engine)

    # ------------------------------------------------------------------ #
    # Sandbox helpers                                                    #
    # ------------------------------------------------------------------ #
    def _sandbox(self):
        """Fresh Trusted Authority for one simulation run."""
        return self.engine.setup()

    @staticmethod
    def _result(attack_id, name, category, goal, steps, blocked, countermeasure, evidence, t0):
        return {
            "id": attack_id,
            "name": name,
            "category": category,
            "attacker_goal": goal,
            "steps": steps,
            "outcome": "BLOCKED" if blocked else "SUCCEEDED",
            "countermeasure": countermeasure,
            "evidence": evidence,
            "duration_ms": _ms(t0),
        }

    # ------------------------------------------------------------------ #
    # 1. Collusion attack                                                #
    # ------------------------------------------------------------------ #
    def collusion(self) -> Dict[str, Any]:
        t0 = time.perf_counter()
        pk, mk = self._sandbox()
        bob = self.engine.keygen(pk, mk, ["Role:Student", "Clearance:Level-3"])
        david = self.engine.keygen(pk, mk, ["Role:Engineer", "Clearance:Level-2"])

        secret = self.engine.random_message()
        ct, formatted = self.engine.encrypt(pk, secret, CORE_POLICY)

        _, bob_reason = self.engine.decrypt_detailed(pk, bob, ct)
        _, david_reason = self.engine.decrypt_detailed(pk, david, ct)

        role = CharmEngine.format_attribute("Role:Engineer")
        clr = CharmEngine.format_attribute("Clearance:Level-3")
        # Frankenstein key: David's Engineer component + Bob's Level-3 component.
        # Together the *labels* satisfy the policy.
        merged = {
            "D": david["D"],
            "Dj": {role: david["Dj"][role], clr: bob["Dj"][clr]},
            "Djp": {role: david["Djp"][role], clr: bob["Djp"][clr]},
            "S": [role, clr],
        }
        recovered, merged_reason = self.engine.decrypt_detailed(pk, merged, ct)
        blocked = recovered is None or recovered != secret

        return self._result(
            "collusion",
            "Collusion Attack (Key Merging)",
            "CP-ABE core",
            "Bob (Student, Level-3) and David (Engineer, Level-2) each fail the policy. "
            "They pool their private-key components so the combined attributes "
            "{Engineer, Level-3} satisfy it.",
            [
                f"Sandbox authority encrypts a session secret under: {formatted}",
                f"Bob alone tries to decrypt -> {bob_reason}",
                f"David alone tries to decrypt -> {david_reason}",
                "Attackers build a merged key: D from David, attribute components "
                f"{role} (David) + {clr} (Bob)",
                f"Merged key decryption -> {merged_reason}",
            ],
            blocked,
            "BSW07 binds every key component to a per-user random r (D = g^((alpha+r)/beta), "
            "D_j = g^r * H(j)^r_j). Components from different users carry different r, so "
            "e(g,g)^(r*s) never cancels and the blinding factor can't be removed. Charm's "
            "ciphertext integrity seal then rejects the wrong session element.",
            {
                "bob_alone": bob_reason,
                "david_alone": david_reason,
                "merged_key": merged_reason,
                "session_secret_recovered": not blocked,
            },
            t0,
        )

    # ------------------------------------------------------------------ #
    # 2. Policy tampering / ciphertext relabelling                       #
    # ------------------------------------------------------------------ #
    def policy_tampering(self) -> Dict[str, Any]:
        t0 = time.perf_counter()
        pk, mk = self._sandbox()
        bob = self.engine.keygen(pk, mk, ["Role:Student", "Clearance:Level-3"])
        secret = self.engine.random_message()
        ct, formatted = self.engine.encrypt(pk, secret, CORE_POLICY)

        src = CharmEngine.format_attribute("Role:Engineer")
        dst = CharmEngine.format_attribute("Role:Student")

        def relabel(d):
            return {k.replace(src, dst): v for k, v in d.items()}

        forged = dict(ct)
        forged["policy"] = ct["policy"].replace(src, dst)
        forged["Cy"] = relabel(ct["Cy"])
        forged["Cyp"] = relabel(ct["Cyp"])
        forged["attributes"] = [a.replace(src, dst) for a in ct["attributes"]]

        recovered, reason = self.engine.decrypt_detailed(pk, bob, forged)
        blocked = recovered is None or recovered != secret

        return self._result(
            "policy_tampering",
            "Policy Tampering (Ciphertext Relabelling)",
            "CP-ABE core",
            "Bob (Student) has write access to storage. He edits the stored ciphertext so the "
            "policy says Role:Student instead of Role:Engineer, then decrypts with his own key.",
            [
                f"Original policy: {formatted}",
                f"Forged policy:   {forged['policy']}",
                f"Ciphertext components C_y / C'_y relabelled {src} -> {dst}",
                f"Bob decrypts the forged ciphertext -> {reason}",
            ],
            blocked,
            "The policy isn't just metadata: each leaf share is C'_y = H(attribute)^q_y(0). "
            "Renaming the label doesn't change the hash baked into the group element, so the "
            "pairing equation fails, and the AEAD seal over the ciphertext detects the edit.",
            {"decryption_result": reason, "session_secret_recovered": not blocked},
            t0,
        )

    # ------------------------------------------------------------------ #
    # 3. Ciphertext tampering against the DEM (AES-256-GCM)              #
    # ------------------------------------------------------------------ #
    def ciphertext_tamper(self) -> Dict[str, Any]:
        t0 = time.perf_counter()
        pk, mk = self._sandbox()
        alice = self.engine.keygen(pk, mk, ["Role:Engineer", "Clearance:Level-3"])
        document = b"%PDF-1.4 CONFIDENTIAL: Project Atlas salary bands. Budget = 4,200,000"
        pkg = self.hybrid.encrypt_document(pk, document, CORE_POLICY)

        baseline_ok = self.hybrid.decrypt_document(pk, alice, pkg) == document

        trials = []
        raw = bytearray(base64.b64decode(pkg["aes_ciphertext"]))
        for label, idx in (("first byte", 0), ("middle byte", len(raw) // 2), ("last byte", len(raw) - 1)):
            mutated = bytearray(raw)
            mutated[idx] ^= 0x01  # single bit flip
            forged = dict(pkg, aes_ciphertext=base64.b64encode(bytes(mutated)).decode())
            try:
                self.hybrid.decrypt_document(pk, alice, forged)
                trials.append({"target": f"ciphertext {label}", "detected": False})
            except TamperError:
                trials.append({"target": f"ciphertext {label}", "detected": True})

        tag = bytearray(base64.b64decode(pkg["tag"]))
        tag[0] ^= 0x80
        try:
            self.hybrid.decrypt_document(pk, alice, dict(pkg, tag=base64.b64encode(bytes(tag)).decode()))
            trials.append({"target": "GCM tag", "detected": False})
        except TamperError:
            trials.append({"target": "GCM tag", "detected": True})

        blocked = baseline_ok and all(t["detected"] for t in trials)
        return self._result(
            "ciphertext_tamper",
            "Ciphertext Tampering (Bit-Flip)",
            "Integrity",
            "A malicious storage provider flips bits in an encrypted document hoping to alter "
            "its content (e.g. change a figure) without being noticed.",
            [
                f"Authorized user (Alice) decrypts untouched file -> {'OK' if baseline_ok else 'FAIL'}",
            ] + [
                f"Flip 1 bit in {t['target']} -> {'REJECTED (tag mismatch)' if t['detected'] else 'ACCEPTED'}"
                for t in trials
            ],
            blocked,
            "AES-256-GCM is authenticated encryption: the 128-bit tag is a MAC over the "
            "ciphertext. Any modification makes decrypt_and_verify() fail before a single "
            "plaintext byte is released (no padding oracle, no malleability).",
            {"baseline_decrypt_ok": baseline_ok, "trials": trials},
            t0,
        )

    # ------------------------------------------------------------------ #
    # 4. Revoked-key replay after epoch rotation                         #
    # ------------------------------------------------------------------ #
    def revoked_key(self) -> Dict[str, Any]:
        t0 = time.perf_counter()
        pk, mk = self._sandbox()
        old_key = self.engine.keygen(pk, mk, ["Role:Engineer", "Clearance:Level-3", "Epoch:1"])
        new_key = self.engine.keygen(pk, mk, ["Role:Engineer", "Clearance:Level-3", "Epoch:2"])
        doc = b"Quarterly roadmap - epoch 2 edition"

        pkg_e1 = self.hybrid.encrypt_document(pk, doc, f"({CORE_POLICY}) AND Epoch:1")
        old_on_e1 = self.hybrid.decrypt_document(pk, old_key, pkg_e1) == doc

        pkg_e2 = self.hybrid.encrypt_document(pk, doc, f"({CORE_POLICY}) AND Epoch:2")
        try:
            self.hybrid.decrypt_document(pk, old_key, pkg_e2)
            old_on_e2 = "GRANTED"
        except AccessDeniedError:
            old_on_e2 = "DENIED"
        new_on_e2 = "GRANTED" if self.hybrid.decrypt_document(pk, new_key, pkg_e2) == doc else "DENIED"

        blocked = old_on_e2 == "DENIED" and new_on_e2 == "GRANTED"
        return self._result(
            "revoked_key",
            "Revoked Key Replay",
            "Key lifecycle",
            "An employee who left keeps a copy of their old private key (Epoch:1) and tries "
            "to open documents after the admin rotated the system to Epoch 2.",
            [
                f"Before rotation: old key opens Epoch-1 document -> {'GRANTED' if old_on_e1 else 'DENIED'}",
                "Admin advances epoch 1 -> 2 and re-encrypts the document under '... AND Epoch:2'",
                f"Old (revoked) key on re-encrypted document -> {old_on_e2}",
                f"Re-issued Epoch-2 key on re-encrypted document -> {new_on_e2}",
            ],
            blocked,
            "Epoch-based revocation: the epoch is an attribute inside the access tree, so a "
            "key without Epoch:2 can't satisfy the new policy. Old keys die mathematically "
            "without regenerating the master key or touching other users.",
            {"old_key_before": old_on_e1, "old_key_after": old_on_e2, "new_key_after": new_on_e2},
            t0,
        )

    # ------------------------------------------------------------------ #
    # 5. Password brute force (online + offline)                         #
    # ------------------------------------------------------------------ #
    def brute_force(self) -> Dict[str, Any]:
        from utils.auth import hash_password, verify_password
        from utils.rate_limit import LoginRateLimiter

        t0 = time.perf_counter()
        victim_password = "Sunshine#42"
        stored = hash_password(victim_password)
        wordlist = [
            "123456", "password", "qwerty", "letmein", "admin123", "iloveyou",
            "Welcome1", "Summer2026", victim_password, "dragon",
        ]

        limiter = LoginRateLimiter(max_failures=5, window_seconds=300, lockout_seconds=60)
        attempts: List[Dict[str, Any]] = []
        cracked = False
        for guess in wordlist:
            if limiter.retry_after("victim", "203.0.113.7"):
                attempts.append({"guess": guess, "result": "LOCKED_OUT"})
                continue
            if verify_password(guess, stored):
                cracked = True
                attempts.append({"guess": guess, "result": "CORRECT"})
                break
            limiter.register_failure("victim", "203.0.113.7")
            attempts.append({"guess": guess, "result": "WRONG"})

        # Offline cost: attacker stole the DB and runs guesses locally.
        salt = os.urandom(16)
        t = time.perf_counter()
        for _ in range(3):
            hashlib.pbkdf2_hmac("sha256", b"guess", salt, 100_000)
        pbkdf2_ms = (time.perf_counter() - t) * 1000 / 3
        t = time.perf_counter()
        for _ in range(20000):
            hashlib.sha256(b"guess").digest()
        sha_ms = (time.perf_counter() - t) * 1000 / 20000

        space = 94 ** 8
        pbkdf2_years = space * (pbkdf2_ms / 1000) / (3600 * 24 * 365)
        sha_years = space * (sha_ms / 1000) / (3600 * 24 * 365)

        guesses_before_lock = sum(1 for a in attempts if a["result"] == "WRONG")
        return self._result(
            "brute_force",
            "Password Brute Force",
            "Authentication",
            "Guess a user's password (which also unlocks their envelope-encrypted CP-ABE key) "
            "online via the login API, or offline after stealing the database.",
            [
                f"Online dictionary attack with {len(wordlist)} guesses (correct one is #{wordlist.index(victim_password) + 1})",
                f"Rate limiter locked the account after {guesses_before_lock} wrong guesses",
                f"Remaining guesses refused with HTTP 429 -> password {'CRACKED' if cracked else 'NOT cracked'}",
                f"Offline: one PBKDF2-SHA256 (100k iter) guess costs {pbkdf2_ms:.1f} ms vs {sha_ms * 1000:.2f} us for plain SHA-256",
                f"Exhausting 94^8 passwords on one core: {pbkdf2_years:,.0f} years (PBKDF2) vs {sha_years:,.0f} years (SHA-256)",
            ],
            not cracked,
            "Online: per-(username, IP) lockout after 5 failures in 5 minutes (HTTP 429 + "
            "Retry-After). Offline: salted PBKDF2-HMAC-SHA256 with 100,000 iterations makes "
            "each guess ~100,000x more expensive than a bare hash; per-user salts defeat "
            "rainbow tables.",
            {
                "attempts": attempts,
                "cracked": cracked,
                "pbkdf2_ms_per_guess": round(pbkdf2_ms, 2),
                "sha256_us_per_guess": round(sha_ms * 1000, 3),
                "slowdown_factor": round(pbkdf2_ms / sha_ms) if sha_ms else None,
                "years_to_exhaust_8char_pbkdf2": round(pbkdf2_years),
            },
            t0,
        )

    # ------------------------------------------------------------------ #
    # 6. Timing side channel (username enumeration)                      #
    # ------------------------------------------------------------------ #
    def timing_leak(self) -> Dict[str, Any]:
        from utils.auth import hash_password, verify_password

        t0 = time.perf_counter()
        real_hash = hash_password("CorrectHorse!9")
        dummy_hash = hash_password(os.urandom(8).hex())
        runs = 6
        probes: Dict[str, Callable[[], Any]] = {
            "existing": lambda: verify_password("wrong-guess", real_hash),
            "naive": lambda: None,  # vulnerable code returns before hashing
            "mitigated": lambda: verify_password("wrong-guess", dummy_hash),
        }
        samples: Dict[str, List[float]] = {k: [] for k in probes}
        # Interleave the probes so CPU frequency / scheduler drift hits all equally
        for _ in range(runs):
            for name, fn in probes.items():
                t = time.perf_counter()
                fn()
                samples[name].append((time.perf_counter() - t) * 1000)
        existing = statistics.median(samples["existing"])
        naive_unknown = statistics.median(samples["naive"])
        mitigated_unknown = statistics.median(samples["mitigated"])

        naive_gap = existing - naive_unknown
        mitigated_gap = abs(existing - mitigated_unknown)
        # The leak is "closed" when the remaining gap is small relative to both the
        # original leak and the response time itself (i.e. lost in network jitter).
        blocked = mitigated_gap < 0.5 * naive_gap

        return self._result(
            "timing_leak",
            "Timing Side Channel (Username Enumeration)",
            "Side channel",
            "Measure how long the login endpoint takes to reject a wrong password. If unknown "
            "usernames are rejected faster, the attacker learns which accounts exist.",
            [
                f"Existing user, wrong password: {existing:.1f} ms (one PBKDF2 run)",
                f"Unknown user, naive code:      {naive_unknown:.3f} ms -> {naive_gap:.1f} ms gap leaks existence",
                f"Unknown user, SecureVault:     {mitigated_unknown:.1f} ms -> gap only {mitigated_gap:.1f} ms",
            ],
            blocked,
            "Login always performs exactly one PBKDF2 verification, against a dummy hash when "
            "the username doesn't exist, and compares digests with hmac.compare_digest "
            "(constant time). Both failure paths return the same generic 401 message.",
            {
                "existing_user_ms": round(existing, 2),
                "naive_unknown_user_ms": round(naive_unknown, 4),
                "mitigated_unknown_user_ms": round(mitigated_unknown, 2),
                "naive_gap_ms": round(naive_gap, 2),
                "mitigated_gap_ms": round(mitigated_gap, 2),
            },
            t0,
        )

    # ------------------------------------------------------------------ #
    # Registry                                                           #
    # ------------------------------------------------------------------ #
    def registry(self) -> Dict[str, Callable[[], Dict[str, Any]]]:
        return {
            "collusion": self.collusion,
            "policy_tampering": self.policy_tampering,
            "ciphertext_tamper": self.ciphertext_tamper,
            "revoked_key": self.revoked_key,
            "brute_force": self.brute_force,
            "timing_leak": self.timing_leak,
        }

    def run(self, attack_id: str) -> Dict[str, Any]:
        fn = self.registry().get(attack_id)
        if fn is None:
            raise KeyError(attack_id)
        return fn()

    def run_all(self) -> List[Dict[str, Any]]:
        return [fn() for fn in self.registry().values()]


ATTACK_CATALOG = [
    {"id": "collusion", "name": "Collusion Attack (Key Merging)", "category": "CP-ABE core"},
    {"id": "policy_tampering", "name": "Policy Tampering (Ciphertext Relabelling)", "category": "CP-ABE core"},
    {"id": "ciphertext_tamper", "name": "Ciphertext Tampering (Bit-Flip)", "category": "Integrity"},
    {"id": "revoked_key", "name": "Revoked Key Replay", "category": "Key lifecycle"},
    {"id": "brute_force", "name": "Password Brute Force", "category": "Authentication"},
    {"id": "timing_leak", "name": "Timing Side Channel (Username Enumeration)", "category": "Side channel"},
]
