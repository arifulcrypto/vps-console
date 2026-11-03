"""The full check: SSH facts, IP info, return routes, reachability, Cloudflare, proxies.

Quick mode: facts, IP info, Shanghai routes, TCP/TLS on the chosen ports from
abroad and from the China probe.
Deep mode adds: all nine carrier routes, the probe's forward route, TLS on
every port, Globalping probes in China.
"""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
import time
from dataclasses import dataclass, field

from . import cloudflare, globalping, netinfo, reach, routes
from .assess import assess, score
from .facts import FACTS_SCRIPT, parse_facts
from .proxy import parse_proxy, test_proxy
from .ssh import SSHError, SSHTarget, connect, run


@dataclass
class CheckOptions:
    mode: str = "quick"
    ports: list[int] = field(default_factory=list)
    sni: str = ""
    domain: str = ""
    cf_token: str = field(default="", repr=False)
    proxies: list[str] = field(default_factory=list, repr=False)
    proxy_scheme: str = "socks5"
    routes: bool = True
    globalping_token: str = field(default="", repr=False)


async def tls_handshake(host: str, port: int, sni: str = "", timeout: float = 6) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni or None), timeout)
    except ConnectionResetError:
        return "reset"
    except (OSError, ssl.SSLError, TimeoutError):
        return "fail"
    writer.close()
    return "ok"


async def resolve_ip(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    found = await cloudflare.resolve(host)
    return found[0] if found else host


async def run_server_check(target: SSHTarget | None, opts: CheckOptions, probe: SSHTarget | None,
                           progress, host: str = "") -> dict:
    """target: SSH login, or None for a network-only check of `host` (or opts.domain)."""
    deep = opts.mode == "deep"
    started = time.time()
    result: dict = {"mode": opts.mode, "started": started}
    host = target.host if target else (host or opts.domain or "")
    ip = await resolve_ip(host) if host else ""
    result["ip"] = ip

    # 1. SSH facts and return routes
    if target:
        await progress("ssh")
        try:
            conn = await connect(target)
        except SSHError as exc:
            result["ssh"] = {"ok": False, "code": exc.code}
        else:
            result["ssh"] = {"ok": True}
            async with conn:
                await progress("facts")
                res = await run(conn, "bash -s", timeout=60, stdin=FACTS_SCRIPT)
                facts = parse_facts(res.stdout)
                result["facts"] = facts
                result["findings"] = assess(facts)
                result["score"] = score(result["findings"])
                info = await netinfo.lookup(ip) if netinfo.is_public_ip(ip) else {"ok": False}
                result["ipinfo"] = info
                if opts.routes:
                    await progress("routes")
                    result["routes"] = await routes.trace_from(
                        conn, routes.pick_targets(opts.mode), info.get("country_code", ""))
    if "ipinfo" not in result and netinfo.is_public_ip(ip):
        result["ipinfo"] = await netinfo.lookup(ip)

    # 2. Reachability from abroad and from China
    ports = list(opts.ports)
    if not ports:
        ports = [target.port] if target else []
        ports.append(443)
        if deep and result.get("facts"):
            for item in result["facts"]["listeners"]:
                if item["public"] and item["proto"] == "tcp" and item["port"] not in ports:
                    ports.append(item["port"])
        ports = ports[:10]
    tls_ports = {p: opts.sni for p in ports} if deep else ({443: opts.sni} if 443 in ports else {})
    if ip:
        await progress("reach")
        abroad = await reach.from_here(ip, ports)
        abroad["tls"] = {str(p): await tls_handshake(ip, p, sni) for p, sni in tls_ports.items()}
        china = None
        probe_error = ""
        forward = None
        if probe:
            try:
                pconn = await connect(probe)
            except SSHError as exc:
                probe_error = exc.code
            else:
                async with pconn:
                    china = await reach.from_probe(pconn, ip, ports, tls_ports)
                    if deep:
                        await progress("forward_route")
                        fwd = await routes.trace_from(pconn, [{"city": "probe", "carrier": "probe", "ip": ip}])
                        forward = fwd[0] if fwd else None
        gp = None
        if deep or not probe:
            await progress("globalping")
            icmp, tcp = await asyncio.gather(
                globalping.measure(ip, token=opts.globalping_token),
                globalping.measure(ip, port=ports[0], token=opts.globalping_token),
            )
            gp = {"icmp": icmp, "tcp": tcp}
            if china is None:
                # Without our own probe, Globalping is the China view.
                tcp_ok = globalping.reachable(tcp.get("results", [])) if tcp.get("ok") else None
                icmp_ok = globalping.reachable(icmp.get("results", [])) if icmp.get("ok") else None
                if tcp_ok is not None:
                    china = {"icmp": {"ok": icmp_ok}, "ports": {str(ports[0]): 1.0 if tcp_ok else None},
                             "tls": {}, "source": "globalping"}
                    abroad_subset = {"icmp": abroad["icmp"], "ports": {str(ports[0]): abroad["ports"][str(ports[0])]}}
                    result["reach"] = {"abroad": abroad, "china": china, "globalping": gp,
                                       **reach.classify(abroad_subset, china, abroad["tls"])}
        if "reach" not in result:
            result["reach"] = {"abroad": abroad, "china": china, "globalping": gp, "probe_error": probe_error,
                               **reach.classify(abroad, china, abroad["tls"])}
        if china is not None and "source" not in china:
            china["source"] = "probe"
        result["reach"]["ports_tested"] = ports
        if forward:
            result["forward_route"] = forward
        result["links"] = reach.manual_links(ip, ports)

    # 3. Cloudflare
    if opts.cf_token:
        await progress("cloudflare")
        result["cloudflare"] = await cloudflare.check(opts.cf_token, opts.domain, ip)

    # 4. Proxies
    if opts.proxies:
        await progress("proxies")
        tested = []
        for line in opts.proxies[:10]:
            try:
                spec = parse_proxy(line, opts.proxy_scheme)
            except ValueError:
                tested.append({"ok": False, "proxy": "?", "error": "unparseable"})
                continue
            tested.append(await test_proxy(spec))
        result["proxies"] = tested

    result["duration_s"] = round(time.time() - started, 1)
    return result
