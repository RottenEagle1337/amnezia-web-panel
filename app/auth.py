"""Single-admin session auth: HMAC-signed cookie, no extra dependencies."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time

from fastapi import Request
from fastapi.responses import RedirectResponse

COOKIE_NAME = "panel_session"
SESSION_TTL = 12 * 3600  # seconds

HASH_ITERATIONS = 600_000


def hash_password(password: str, salt: bytes | None = None) -> str:
    """PBKDF2-SHA256 in a self-describing format: pbkdf2$iters$salt_hex$hash_hex."""
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, HASH_ITERATIONS)
    return f"pbkdf2${HASH_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(stored: str, candidate: str) -> bool:
    try:
        _, iters, salt_hex, hash_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac(
            "sha256", candidate.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


class Auth:
    def __init__(self, password: str) -> None:
        # Accepts either a pbkdf2$ hash (prod, from .env) or plaintext (dev/mock).
        self._stored = password if password.startswith("pbkdf2$") else hash_password(password)
        # Per-process salt: sessions die on restart, that is fine for a LAN panel.
        self._secret = secrets.token_bytes(32)

    def check_password(self, candidate: str) -> bool:
        return verify_password(self._stored, candidate)

    def make_token(self) -> str:
        ts = str(int(time.time()))
        sig = hmac.new(self._secret, ts.encode(), hashlib.sha256).hexdigest()
        return f"{ts}.{sig}"

    def rotate_secret(self) -> None:
        """Invalidate all outstanding tokens (single-admin panel: called on logout)."""
        self._secret = secrets.token_bytes(32)

    def verify_token(self, token: str) -> bool:
        try:
            ts, sig = token.split(".", 1)
            issued = int(ts)
        except ValueError:
            return False
        expected = hmac.new(self._secret, ts.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        age = time.time() - issued
        return 0 <= age < SESSION_TTL


class LoginThrottle:
    """In-memory brute-force guard: max_attempts failures per window per IP."""

    def __init__(self, max_attempts: int = 5, window: int = 300) -> None:
        self.max_attempts = max_attempts
        self.window = window
        self._fails: dict[str, list[float]] = {}

    def allowed(self, key: str) -> bool:
        now = time.time()
        attempts = [t for t in self._fails.get(key, []) if now - t < self.window]
        self._fails[key] = attempts
        return len(attempts) < self.max_attempts

    def record_failure(self, key: str) -> None:
        self._fails.setdefault(key, []).append(time.time())

    def reset(self, key: str) -> None:
        self._fails.pop(key, None)


def require_session(request: Request) -> RedirectResponse | None:
    """Return a redirect to /login when the request has no valid session."""
    auth: Auth = request.app.state.auth
    token = request.cookies.get(COOKIE_NAME, "")
    if not token or not auth.verify_token(token):
        return RedirectResponse("/login", status_code=303)
    return None
