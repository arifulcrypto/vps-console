"""Test servers ("probes"), e.g. a VPS in China used for reachability checks.

Credentials are encrypted with a key kept outside the database and are never
sent back to the browser. By default a submitted password is used once to
install a dedicated SSH key, then thrown away: only the encrypted key stays.
"""

from __future__ import annotations

import shlex
import time

import asyncssh

from .checks.ssh import SSHError, SSHTarget, connect, host_key_of, run
from .db import Database
from .security import SecretBox

KEY_COMMENT = "vps-console-probe"


async def list_probes(db: Database) -> list[dict]:
    rows = await db.fetchall(
        "SELECT id, name, region, host, port, username, auth_type, enabled, secret_set_at, created_at, "
        "host_key != '' AS pinned FROM probes ORDER BY id"
    )
    return rows


async def active_probe(db: Database, box: SecretBox) -> SSHTarget | None:
    row = await db.fetchone("SELECT * FROM probes WHERE enabled = 1 ORDER BY id LIMIT 1")
    if not row:
        return None
    secret = box.decrypt(row["secret_enc"])
    return SSHTarget(
        host=row["host"], port=row["port"], username=row["username"],
        password=secret if row["auth_type"] == "password" else None,
        private_key=secret if row["auth_type"] == "key" else None,
        pinned_host_key=row["host_key"],
    )


async def _install_key(conn: asyncssh.SSHClientConnection) -> tuple[str, str]:
    key = asyncssh.generate_private_key("ssh-ed25519", comment=KEY_COMMENT)
    private = key.export_private_key("openssh").decode()
    public = key.export_public_key("openssh").decode().strip()
    line = shlex.quote(public)
    cmd = (
        "umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && "
        f"(grep -qxF {line} ~/.ssh/authorized_keys || echo {line} >> ~/.ssh/authorized_keys)"
    )
    res = await run(conn, cmd, timeout=20)
    if res.exit_status != 0:
        raise SSHError("key_install_failed", "Could not add the SSH key on the server.")
    return private, public


async def save_probe(db: Database, box: SecretBox, *, name: str, region: str, host: str, port: int,
                     username: str, auth_type: str, secret: str, switch_to_key: bool,
                     probe_id: int | None = None) -> dict:
    """Verify the login, optionally swap the password for a key, store encrypted."""
    target = SSHTarget(host=host, port=port, username=username,
                       password=secret if auth_type == "password" else None,
                       private_key=secret if auth_type == "key" else None)
    conn = await connect(target)
    async with conn:
        host_key = host_key_of(conn)
        if auth_type == "password" and switch_to_key:
            private, _public = await _install_key(conn)
            check = SSHTarget(host=host, port=port, username=username, private_key=private,
                              pinned_host_key=host_key)
            async with await connect(check):
                pass
            auth_type, secret = "key", private
    now = time.time()
    enc = box.encrypt(secret)
    if probe_id:
        await db.execute(
            "UPDATE probes SET name=?, region=?, host=?, port=?, username=?, auth_type=?, secret_enc=?, "
            "host_key=?, secret_set_at=? WHERE id=?",
            (name, region, host, port, username, auth_type, enc, host_key, now, probe_id),
        )
    else:
        await db.execute(
            "INSERT INTO probes (name, region, host, port, username, auth_type, secret_enc, host_key, enabled, "
            "secret_set_at, created_at) VALUES (?,?,?,?,?,?,?,?,1,?,?)",
            (name, region, host, port, username, auth_type, enc, host_key, now, now),
        )
    return {"auth_type": auth_type}


async def update_meta(db: Database, probe_id: int, name: str, region: str, enabled: bool) -> None:
    await db.execute("UPDATE probes SET name=?, region=?, enabled=? WHERE id=?",
                     (name, region, int(enabled), probe_id))


async def test_probe(db: Database, box: SecretBox, probe_id: int) -> dict:
    row = await db.fetchone("SELECT * FROM probes WHERE id = ?", (probe_id,))
    if not row:
        return {"ok": False, "code": "not_found"}
    secret = box.decrypt(row["secret_enc"])
    target = SSHTarget(host=row["host"], port=row["port"], username=row["username"],
                       password=secret if row["auth_type"] == "password" else None,
                       private_key=secret if row["auth_type"] == "key" else None,
                       pinned_host_key=row["host_key"])
    try:
        conn = await connect(target)
    except SSHError as exc:
        return {"ok": False, "code": exc.code}
    async with conn:
        res = await run(conn, "command -v mtr >/dev/null && echo mtr; command -v openssl >/dev/null && echo openssl;"
                              " curl -s -m 8 https://www.cloudflare.com/cdn-cgi/trace | grep -E '^loc='", timeout=20)
    tools = res.stdout.split()
    return {"ok": True, "tools": [t for t in tools if not t.startswith("loc=")],
            "loc": next((t[4:] for t in tools if t.startswith("loc=")), "")}


async def delete_probe(db: Database, box: SecretBox, probe_id: int) -> None:
    """Remove the stored probe, and our key from its authorized_keys when we can reach it."""
    row = await db.fetchone("SELECT * FROM probes WHERE id = ?", (probe_id,))
    if not row:
        return
    if row["auth_type"] == "key":
        try:
            secret = box.decrypt(row["secret_enc"])
            target = SSHTarget(host=row["host"], port=row["port"], username=row["username"],
                               private_key=secret, pinned_host_key=row["host_key"])
            public = asyncssh.import_private_key(secret).export_public_key("openssh").decode().strip()
            async with await connect(target, timeout=10) as conn:
                quoted = shlex.quote(public)
                await run(conn, f"grep -vxF {quoted} ~/.ssh/authorized_keys > ~/.ssh/.ak.tmp; "
                                "cat ~/.ssh/.ak.tmp > ~/.ssh/authorized_keys; rm -f ~/.ssh/.ak.tmp", timeout=20)
        except (SSHError, ValueError, OSError):
            pass
    await db.execute("DELETE FROM probes WHERE id = ?", (probe_id,))
