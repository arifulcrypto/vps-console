"""Reachability from abroad and from China, and GFW block classification.

Block types this can tell apart:
- ip_blocked: nothing answers from China, but it works from abroad.
- port_blocked: some ports fail from China only.
- tls_interference: TCP connects from China but the TLS handshake is cut.
A protocol block of a proxy that still completes TLS needs a real client
test from inside China, which is outside these checks.
"""

from __future__ import annotations

import asyncio
import re
import shlex
import time

from .ssh import run


async def tcp_connect(host: str, port: int, timeout: float = 4) -> float | None:
    start = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, asyncio.TimeoutError, TimeoutError):
        return None
    elapsed = (time.perf_counter() - start) * 1000
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return round(elapsed, 1)


async def icmp_ping(host: str, count: int = 3) -> dict:
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-n", "-c", str(count), "-W", "2", host,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=count * 3 + 5)
    except (OSError, asyncio.TimeoutError, TimeoutError):
        return {"ok": None, "loss": None, "avg": None}
    return parse_ping(out.decode(errors="replace"))


def parse_ping(text: str) -> dict:
    loss = re.search(r"([\d.]+)% packet loss", text)
    avg = re.search(r"= [\d.]+/([\d.]+)/", text)
    loss_v = float(loss.group(1)) if loss else None
    return {"ok": (loss_v is not None and loss_v < 100), "loss": loss_v, "avg": float(avg.group(1)) if avg else None}


async def from_here(host: str, ports: list[int]) -> dict:
    ping, *conns = await asyncio.gather(icmp_ping(host), *(tcp_connect(host, p) for p in ports))
    return {"icmp": ping, "ports": {str(p): ms for p, ms in zip(ports, conns)}}


def probe_script(host: str, ports: list[int], tls_ports: dict[int, str]) -> str:
    """Shell run on the China probe. Prints one line per test."""
    h = shlex.quote(host)
    lines = [
        "export LC_ALL=C",
        f"echo PING; ping -n -c 4 -W 2 {h} 2>&1 | tail -n 3",
        "ms(){ echo $(( ($(date +%s%N) - $1) / 1000000 )); }",
    ]
    for p in ports:
        lines.append(
            f"s=$(date +%s%N); if timeout 4 bash -c 'exec 3<>/dev/tcp/{host}/{int(p)}' 2>/dev/null; "
            f"then echo \"TCP {int(p)} open $(ms $s)\"; else echo \"TCP {int(p)} fail $(ms $s)\"; fi"
        )
    for p, sni in tls_ports.items():
        s = shlex.quote(sni or host)
        lines.append(
            f"r=$(timeout 7 openssl s_client -connect {h}:{int(p)} -servername {s} </dev/null 2>&1); "
            f"if echo \"$r\" | grep -q 'BEGIN CERTIFICATE\\|Protocol version\\|Cipher is'; then echo \"TLS {int(p)} ok\"; "
            f"elif echo \"$r\" | grep -qi 'reset\\|errno=104'; then echo \"TLS {int(p)} reset\"; "
            f"else echo \"TLS {int(p)} fail\"; fi"
        )
    return "\n".join(lines)


def parse_probe(text: str) -> dict:
    result: dict = {"icmp": parse_ping(text), "ports": {}, "tls": {}}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "TCP":
            result["ports"][parts[1]] = float(parts[3]) if parts[2] == "open" and len(parts) > 3 else None
        elif len(parts) >= 3 and parts[0] == "TLS":
            result["tls"][parts[1]] = parts[2]
    return result


async def from_probe(conn, host: str, ports: list[int], tls_ports: dict[int, str]) -> dict:
    res = await run(conn, "bash -s", timeout=120, stdin=probe_script(host, ports, tls_ports))
    return parse_probe(res.stdout)


def classify(abroad: dict, china: dict | None, tls_abroad: dict | None = None) -> dict:
    """Compare abroad and China views of the same ports."""
    abroad_open = {p for p, ms in abroad["ports"].items() if ms is not None}
    if not abroad_open and not abroad["icmp"].get("ok"):
        return {"verdict": "down", "ports": []}
    if not china:
        return {"verdict": "no_china_data", "ports": []}
    china_open = {p for p, ms in china["ports"].items() if ms is not None}
    china_icmp = china["icmp"].get("ok")
    blocked = sorted(abroad_open - china_open, key=int)
    if abroad_open and not china_open and not china_icmp:
        return {"verdict": "ip_blocked", "ports": blocked}
    if blocked:
        return {"verdict": "port_blocked", "ports": blocked}
    cut = sorted((p for p, state in china.get("tls", {}).items()
                  if state in ("reset", "fail") and p in china_open
                  and (tls_abroad is None or tls_abroad.get(p, "ok") == "ok")), key=int)
    if cut:
        return {"verdict": "tls_interference", "ports": cut}
    return {"verdict": "reachable", "ports": []}


def manual_links(host: str, ports: list[int]) -> list[dict]:
    first = ports[0] if ports else 443
    links = [
        {"name": "ITDOG ping", "url": f"https://www.itdog.cn/ping/{host}"},
        {"name": "ping.pe", "url": f"https://ping.pe/{host}"},
        {"name": "IP.NET.COFFEE", "url": "https://ip.net.coffee/link/"},
    ]
    for p in ports[:4]:
        links.insert(1, {"name": f"ITDOG TCP {p}", "url": f"https://www.itdog.cn/tcping/{host}:{p}"})
    links.insert(2, {"name": f"tcp.ping.pe {first}", "url": f"https://tcp.ping.pe/{host}:{first}"})
    return links
