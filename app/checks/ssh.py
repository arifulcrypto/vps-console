"""SSH access for checks. Read-only commands only; nothing here changes a target."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import asyncssh


class SSHError(Exception):
    """A connection or login problem, with a message safe to show the user."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class SSHTarget:
    host: str
    port: int = 22
    username: str = "root"
    password: str | None = field(default=None, repr=False)
    private_key: str | None = field(default=None, repr=False)
    pinned_host_key: str = ""

    def label(self) -> str:
        return f"{self.username}@{self.host}:{self.port}"


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    exit_status: int | None


async def connect(target: SSHTarget, timeout: float = 15) -> asyncssh.SSHClientConnection:
    if not (target.password or target.private_key):
        raise SSHError("no_credentials", "Enter a password or a private key.")
    client_keys = None
    if target.private_key:
        try:
            client_keys = [asyncssh.import_private_key(target.private_key)]
        except (asyncssh.KeyImportError, ValueError) as exc:
            raise SSHError("bad_key", "The private key could not be read. Encrypted keys are not supported.") from exc
    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(
                target.host,
                port=target.port,
                username=target.username,
                password=target.password,
                client_keys=client_keys,
                known_hosts=None,
                config=None,
                agent_path=None,
                connect_timeout=timeout,
                login_timeout=timeout,
                keepalive_interval=20,
            ),
            timeout=timeout + 5,
        )
    except asyncssh.PermissionDenied as exc:
        raise SSHError("auth_failed", "Login refused: wrong user, password or key.") from exc
    except (asyncio.TimeoutError, TimeoutError) as exc:
        raise SSHError("timeout", "No SSH answer in time. Check the IP, port and firewall.") from exc
    except ConnectionRefusedError as exc:
        raise SSHError("refused", "Connection refused: nothing listens on that port.") from exc
    except (OSError, asyncssh.Error) as exc:
        raise SSHError("connect_failed", f"SSH connection failed: {exc.__class__.__name__}.") from exc

    if target.pinned_host_key:
        key = host_key_of(conn)
        if key != target.pinned_host_key:
            conn.close()
            raise SSHError(
                "host_key_changed",
                "The server's host key changed since it was saved. Re-save the server if you rebuilt it.",
            )
    return conn


def host_key_of(conn: asyncssh.SSHClientConnection) -> str:
    key = conn.get_server_host_key()
    return key.export_public_key("openssh").decode().strip() if key else ""


async def run(conn: asyncssh.SSHClientConnection, command: str, timeout: float = 60,
              stdin: str | None = None) -> CommandResult:
    try:
        result = await asyncio.wait_for(conn.run(command, input=stdin, check=False), timeout=timeout)
    except (asyncio.TimeoutError, TimeoutError):
        return CommandResult("", "timed out", None)
    return CommandResult(str(result.stdout or ""), str(result.stderr or ""), result.exit_status)
