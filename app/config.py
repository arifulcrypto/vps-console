"""Runtime settings, read from environment variables.

Secrets never live in the repository. Production reads them from files under
/etc/vps-console (see deploy/bootstrap.sh); tests and local runs get throwaway
values generated on first start inside DATA_DIR.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path


def _read_or_create(path: Path, factory) -> str:
    if path.exists():
        return path.read_text().strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    value = factory()
    path.write_text(value)
    path.chmod(0o600)
    return value


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    secret_dir: Path
    base_url: str
    secure_cookies: bool
    version: str
    max_concurrent_jobs: int = 3

    @property
    def db_path(self) -> Path:
        return self.data_dir / "app.db"

    def session_key(self) -> str:
        return _read_or_create(self.secret_dir / "session.key", lambda: secrets.token_urlsafe(48))

    def encryption_key(self) -> str:
        from cryptography.fernet import Fernet

        return _read_or_create(self.secret_dir / "fernet.key", lambda: Fernet.generate_key().decode())


def load_settings() -> Settings:
    data_dir = Path(os.environ.get("VPSC_DATA_DIR", "./var"))
    secret_dir = Path(os.environ.get("VPSC_SECRET_DIR", str(data_dir / "secrets")))
    return Settings(
        data_dir=data_dir,
        secret_dir=secret_dir,
        base_url=os.environ.get("VPSC_BASE_URL", "http://127.0.0.1:8091").rstrip("/"),
        secure_cookies=os.environ.get("VPSC_SECURE_COOKIES", "0") == "1",
        version=os.environ.get("VPSC_VERSION", "dev"),
        max_concurrent_jobs=int(os.environ.get("VPSC_MAX_JOBS", "3")),
    )
