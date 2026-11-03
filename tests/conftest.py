import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.security import hash_password

ADMIN_PASSWORD = "correct horse battery staple"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(data_dir=tmp_path, secret_dir=tmp_path / "secrets", base_url="https://tools.example.com",
                    secure_cookies=False, version="testsha")


@pytest.fixture
def app(settings):
    return create_app(settings)


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        import asyncio
        import time

        asyncio.run(app.state.db.execute(
            "INSERT INTO admin (id, username, password_hash, updated_at) VALUES (1, 'admin', ?, ?)",
            (hash_password(ADMIN_PASSWORD), time.time())))
        yield c


def csrf_of(html: str) -> str:
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    assert m, "no csrf field on page"
    return m.group(1)


@pytest.fixture
def admin(client):
    page = client.get("/login")
    resp = client.post("/login", data={"username": "admin", "password": ADMIN_PASSWORD, "next": "/",
                                       "csrf": csrf_of(page.text)}, follow_redirects=False)
    assert resp.status_code == 303
    return client
