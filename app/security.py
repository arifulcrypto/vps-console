"""Password hashing, secret encryption, CSRF and login throttling."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque

from cryptography.fernet import Fernet, InvalidToken

# scrypt parameters: about 16 MB of memory per hash.
_N, _R, _P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return "scrypt${}${}".format(base64.b64encode(salt).decode(), base64.b64encode(digest).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_b64, digest_b64 = stored.split("$")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    salt = base64.b64decode(salt_b64)
    expected = base64.b64decode(digest_b64)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return hmac.compare_digest(digest, expected)


class SecretBox:
    """Encrypts secrets at rest. The key lives outside the database."""

    def __init__(self, key: str):
        self._fernet = Fernet(key.encode() if isinstance(key, str) else key)

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except InvalidToken as exc:  # wrong key or tampered value
            raise ValueError("stored secret cannot be decrypted with the current key") from exc


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_matches(session_token: str | None, submitted: str | None) -> bool:
    return bool(session_token and submitted and hmac.compare_digest(session_token, submitted))


class LoginThrottle:
    """At most `limit` failed logins per client in `window` seconds."""

    def __init__(self, limit: int = 5, window: float = 900):
        self.limit = limit
        self.window = window
        self._fails: dict[str, deque[float]] = defaultdict(deque)

    def _trim(self, key: str, now: float) -> deque[float]:
        q = self._fails[key]
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def blocked(self, key: str) -> bool:
        return len(self._trim(key, time.monotonic())) >= self.limit

    def fail(self, key: str) -> None:
        self._trim(key, time.monotonic()).append(time.monotonic())

    def reset(self, key: str) -> None:
        self._fails.pop(key, None)


def mask(value: str, keep: int = 3) -> str:
    """Show only the end of a value, for confirmations like 'token …abc'."""
    if not value:
        return ""
    return "…" + value[-keep:] if len(value) > keep * 2 else "•" * len(value)
