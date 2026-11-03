"""Fetch a remote subscription safely: public addresses only, size and time limits."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import httpx

MAX_BYTES = 5 * 1024 * 1024
MAX_REDIRECTS = 3


class FetchError(Exception):
    pass


async def _check_public(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise FetchError("only http(s) URLs")
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(parts.hostname, parts.port or 443,
                                                             type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise FetchError("host not found") from exc
    for info in infos:
        if not ipaddress.ip_address(info[4][0]).is_global:
            raise FetchError("private addresses are not allowed")


async def fetch_subscription(url: str, user_agent: str) -> str:
    async with httpx.AsyncClient(timeout=20, follow_redirects=False,
                                 headers={"User-Agent": user_agent[:100]}) as client:
        for _ in range(MAX_REDIRECTS + 1):
            await _check_public(url)
            try:
                async with client.stream("GET", url) as resp:
                    if resp.is_redirect:
                        url = urljoin(url, resp.headers.get("location", ""))
                        continue
                    if resp.status_code >= 400:
                        raise FetchError(f"HTTP {resp.status_code}")
                    body = bytearray()
                    async for chunk in resp.aiter_bytes():
                        body += chunk
                        if len(body) > MAX_BYTES:
                            raise FetchError("larger than 5 MB")
                    return body.decode("utf-8", errors="replace")
            except httpx.HTTPError as exc:
                raise FetchError(exc.__class__.__name__) from exc
    raise FetchError("too many redirects")
