"""
Login brute-force countermeasure.

Tracks failed login attempts per (username, client IP) inside a sliding window.
After MAX_FAILURES failures the pair is locked out for LOCKOUT_SECONDS.

Keying on (username, IP) instead of username alone means an attacker cannot
lock a legitimate user out of their account from a different network
(account-lockout denial of service), while online password guessing from one
source is throttled to MAX_FAILURES guesses per window.

State is in-process memory. That is correct for the single-worker deployment
used here (see Dockerfile); a multi-instance deployment would move it to Redis.
"""
import threading
import time
from typing import Callable, Dict, List, Tuple

MAX_FAILURES = 5
WINDOW_SECONDS = 300
LOCKOUT_SECONDS = 60


class LoginRateLimiter:
    def __init__(
        self,
        max_failures: int = MAX_FAILURES,
        window_seconds: int = WINDOW_SECONDS,
        lockout_seconds: int = LOCKOUT_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._clock = clock
        self._failures: Dict[Tuple[str, str], List[float]] = {}
        self._locked_until: Dict[Tuple[str, str], float] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(username: str, ip: str) -> Tuple[str, str]:
        return (username.strip().lower(), ip or "unknown")

    def retry_after(self, username: str, ip: str) -> int:
        """Seconds until this (username, ip) may try again; 0 if not locked."""
        key = self._key(username, ip)
        with self._lock:
            until = self._locked_until.get(key, 0)
            remaining = until - self._clock()
            if remaining <= 0:
                self._locked_until.pop(key, None)
                return 0
            return int(remaining) + 1

    def register_failure(self, username: str, ip: str) -> bool:
        """Record a failed attempt. Returns True if this failure triggered a lockout."""
        key = self._key(username, ip)
        now = self._clock()
        with self._lock:
            recent = [t for t in self._failures.get(key, []) if now - t < self.window_seconds]
            recent.append(now)
            if len(recent) >= self.max_failures:
                self._locked_until[key] = now + self.lockout_seconds
                self._failures.pop(key, None)
                return True
            self._failures[key] = recent
            return False

    def register_success(self, username: str, ip: str) -> None:
        key = self._key(username, ip)
        with self._lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()
            self._locked_until.clear()


# Process-wide limiter used by the /api/auth/login route
login_limiter = LoginRateLimiter()
