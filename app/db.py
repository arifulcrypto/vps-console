"""SQLite storage with forward-only migrations.

Tables
- admin: the single admin account (scrypt hash).
- probes: test servers such as the China probe. Secrets are Fernet-encrypted
  and never rendered back to the browser.
- settings: small key/value store; values marked secret are encrypted.
- jobs: check runs and their results. Results never contain credentials.
- outputs: generated files (prompt, YAML, links) kept for download.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import aiosqlite

MIGRATIONS = [
    """
    CREATE TABLE admin (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        username TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        updated_at REAL NOT NULL
    );
    CREATE TABLE probes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        region TEXT NOT NULL DEFAULT '',
        host TEXT NOT NULL,
        port INTEGER NOT NULL DEFAULT 22,
        username TEXT NOT NULL DEFAULT 'root',
        auth_type TEXT NOT NULL,
        secret_enc TEXT NOT NULL,
        host_key TEXT NOT NULL DEFAULT '',
        enabled INTEGER NOT NULL DEFAULT 1,
        secret_set_at REAL NOT NULL,
        created_at REAL NOT NULL
    );
    CREATE TABLE settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        secret INTEGER NOT NULL DEFAULT 0,
        updated_at REAL NOT NULL
    );
    CREATE TABLE jobs (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        mode TEXT NOT NULL,
        target TEXT NOT NULL,
        status TEXT NOT NULL,
        progress TEXT NOT NULL DEFAULT '',
        input_json TEXT NOT NULL DEFAULT '{}',
        result_json TEXT NOT NULL DEFAULT '{}',
        created_at REAL NOT NULL,
        finished_at REAL
    );
    CREATE TABLE outputs (
        id TEXT PRIMARY KEY,
        job_id TEXT,
        kind TEXT NOT NULL,
        title TEXT NOT NULL,
        filename TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at REAL NOT NULL
    );
    CREATE TABLE subscriptions (
        token TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at REAL NOT NULL
    );
    """,
]


JOB_COLUMNS = {"status", "progress", "result_json", "finished_at"}


class Database:
    def __init__(self, path: Path):
        self.path = path

    async def connect(self) -> aiosqlite.Connection:
        conn = await aiosqlite.connect(self.path)
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA foreign_keys = ON")
        return conn

    async def migrate(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("PRAGMA journal_mode = WAL")
            version = (await (await conn.execute("PRAGMA user_version")).fetchone())[0]
            for index, script in enumerate(MIGRATIONS[version:], start=version + 1):
                await conn.executescript(script)
                await conn.execute(f"PRAGMA user_version = {index}")
            await conn.commit()
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    async def fetchone(self, sql: str, params: tuple = ()) -> dict[str, Any] | None:
        async with aiosqlite.connect(self.path) as conn:
            conn.row_factory = aiosqlite.Row
            row = await (await conn.execute(sql, params)).fetchone()
            return dict(row) if row else None

    async def fetchall(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        async with aiosqlite.connect(self.path) as conn:
            conn.row_factory = aiosqlite.Row
            rows = await (await conn.execute(sql, params)).fetchall()
            return [dict(r) for r in rows]

    async def execute(self, sql: str, params: tuple = ()) -> None:
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute(sql, params)
            await conn.commit()

    # Jobs -----------------------------------------------------------------

    async def create_job(self, job_id: str, kind: str, mode: str, target: str, inputs: dict) -> None:
        await self.execute(
            "INSERT INTO jobs (id, kind, mode, target, status, input_json, created_at) VALUES (?,?,?,?,?,?,?)",
            (job_id, kind, mode, target, "running", json.dumps(inputs), time.time()),
        )

    async def update_job(self, job_id: str, **fields: Any) -> None:
        if "result" in fields:
            fields["result_json"] = json.dumps(fields.pop("result"), ensure_ascii=False)
        unknown = set(fields) - JOB_COLUMNS
        if unknown:
            raise ValueError(f"unknown job fields {unknown}")
        cols = ", ".join(f"{k} = ?" for k in fields)  # names come from JOB_COLUMNS, values are bound
        await self.execute(f"UPDATE jobs SET {cols} WHERE id = ?", (*fields.values(), job_id))  # noqa: S608

    async def get_job(self, job_id: str) -> dict[str, Any] | None:
        row = await self.fetchone("SELECT * FROM jobs WHERE id = ?", (job_id,))
        if row:
            row["result"] = json.loads(row.pop("result_json") or "{}")
            row["inputs"] = json.loads(row.pop("input_json") or "{}")
        return row

    # Settings -------------------------------------------------------------

    async def get_setting(self, key: str, default: str = "") -> str:
        row = await self.fetchone("SELECT value FROM settings WHERE key = ?", (key,))
        return row["value"] if row else default

    async def set_setting(self, key: str, value: str, secret: bool = False) -> None:
        await self.execute(
            "INSERT INTO settings (key, value, secret, updated_at) VALUES (?,?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, secret = excluded.secret, "
            "updated_at = excluded.updated_at",
            (key, value, int(secret), time.time()),
        )
