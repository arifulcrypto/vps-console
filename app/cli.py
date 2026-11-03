"""Server-side admin commands.

  python -m app.cli set-admin [--username admin]   prints a new random password once
  python -m app.cli add-probe --name NAME --host IP [--port 22] [--user root] [--keep-password]
      reads the password from stdin, so it never appears in shell history
"""

from __future__ import annotations

import argparse
import asyncio
import secrets
import sys
import time

from .config import load_settings
from .db import Database
from .probes import save_probe
from .security import SecretBox, hash_password


async def set_admin(username: str) -> None:
    settings = load_settings()
    db = Database(settings.db_path)
    await db.migrate()
    password = secrets.token_urlsafe(15)
    await db.execute(
        "INSERT INTO admin (id, username, password_hash, updated_at) VALUES (1, ?, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET username = excluded.username, password_hash = excluded.password_hash, "
        "updated_at = excluded.updated_at",
        (username, hash_password(password), time.time()),
    )
    print(f"admin user: {username}\npassword:   {password}\nShown once. Change it under Account after login.")


async def add_probe(args) -> None:
    settings = load_settings()
    db = Database(settings.db_path)
    await db.migrate()
    secret = sys.stdin.readline().rstrip("\n")
    if not secret:
        sys.exit("password expected on stdin")
    result = await save_probe(db, SecretBox(settings.encryption_key()), name=args.name, region=args.region,
                              host=args.host, port=args.port, username=args.user, auth_type="password",
                              secret=secret, switch_to_key=not args.keep_password)
    print(f"probe saved, auth: {result['auth_type']}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("set-admin")
    a.add_argument("--username", default="admin")
    p = sub.add_parser("add-probe")
    p.add_argument("--name", required=True)
    p.add_argument("--region", default="")
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--user", default="root")
    p.add_argument("--keep-password", action="store_true")
    args = parser.parse_args()
    if args.cmd == "set-admin":
        asyncio.run(set_admin(args.username))
    else:
        asyncio.run(add_probe(args))


if __name__ == "__main__":
    main()
