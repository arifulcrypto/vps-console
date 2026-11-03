"""Test residential, dynamic or static ISP proxies: does it work, where does it exit."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from urllib.parse import quote, unquote, urlsplit

import httpx

from .netinfo import lookup

TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
SCHEMES = {"socks5", "socks5h", "http", "https"}


@dataclass
class ProxySpec:
    scheme: str
    host: str
    port: int
    username: str = ""
    password: str = field(default="", repr=False)

    def url(self) -> str:
        scheme = "socks5" if self.scheme == "socks5h" else self.scheme
        auth = ""
        if self.username:
            auth = f"{quote(self.username, safe='')}:{quote(self.password, safe='')}@"
        return f"{scheme}://{auth}{self.host}:{self.port}"

    def display(self) -> str:
        user = f"{self.username}@" if self.username else ""
        return f"{self.scheme}://{user}{self.host}:{self.port}"


def parse_proxy(text: str, default_scheme: str = "socks5") -> ProxySpec:
    """Accepts scheme://user:pass@host:port, user:pass@host:port and host:port:user:pass."""
    text = text.strip()
    if not text:
        raise ValueError("empty")
    if "://" in text:
        parts = urlsplit(text)
        if parts.scheme not in SCHEMES or not parts.hostname or not parts.port:
            raise ValueError("unsupported proxy URL")
        return ProxySpec(parts.scheme, parts.hostname, parts.port,
                         unquote(parts.username or ""), unquote(parts.password or ""))
    if default_scheme not in SCHEMES:
        raise ValueError("unsupported scheme")
    if "@" in text:
        auth, _, hostport = text.rpartition("@")
        user, _, pw = auth.partition(":")
        host, _, port = hostport.rpartition(":")
        return ProxySpec(default_scheme, host, int(port), user, pw)
    pieces = text.split(":")
    if len(pieces) == 2:
        return ProxySpec(default_scheme, pieces[0], int(pieces[1]))
    if len(pieces) >= 4:
        return ProxySpec(default_scheme, pieces[0], int(pieces[1]), pieces[2], ":".join(pieces[3:]))
    raise ValueError("unrecognised format")


def parse_trace(text: str) -> dict:
    return dict(re.findall(r"^(\w+)=(.*)$", text, re.M))


async def test_proxy(spec: ProxySpec, rounds: int = 2) -> dict:
    exits = []
    latencies = []
    error = ""
    try:
        async with httpx.AsyncClient(proxy=spec.url(), timeout=20) as client:
            for _ in range(rounds):
                start = time.perf_counter()
                resp = await client.get(TRACE_URL)
                latencies.append(round((time.perf_counter() - start) * 1000))
                exits.append(parse_trace(resp.text).get("ip", ""))
    except httpx.ProxyError:
        error = "proxy_refused"
    except (httpx.ConnectTimeout, httpx.ReadTimeout):
        error = "timeout"
    except httpx.HTTPError as exc:
        error = "failed:" + exc.__class__.__name__
    except Exception as exc:  # socks errors surface as various types
        error = "failed:" + exc.__class__.__name__
    if not exits:
        return {"ok": False, "proxy": spec.display(), "error": error or "no_answer"}
    info = await lookup(exits[-1])
    return {
        "ok": True,
        "proxy": spec.display(),
        "exit_ips": exits,
        "sticky": len(set(exits)) == 1,
        "latency_ms": latencies,
        "info": info,
        "error": error,
    }
