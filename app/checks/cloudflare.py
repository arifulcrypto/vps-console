"""Cloudflare token and DNS checks. Read-only: it never changes a record."""

from __future__ import annotations

import ipaddress

import httpx

API = "https://api.cloudflare.com/client/v4"
DOH = "https://cloudflare-dns.com/dns-query"

# https://www.cloudflare.com/ips-v4
CF_V4 = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)]


def is_cloudflare_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in net for net in CF_V4)


def zone_for(domain: str, zones: list[dict]) -> dict | None:
    domain = domain.lower().rstrip(".")
    best = None
    for zone in zones:
        name = zone["name"].lower()
        if (domain == name or domain.endswith("." + name)) and (best is None or len(name) > len(best["name"])):
            best = zone
    return best


async def resolve(domain: str, rtype: str = "A") -> list[str]:
    async with httpx.AsyncClient(timeout=8) as client:
        try:
            resp = await client.get(DOH, params={"name": domain, "type": rtype},
                                    headers={"accept": "application/dns-json"})
            data = resp.json()
        except (httpx.HTTPError, ValueError):
            return []
    want = {"A": 1, "AAAA": 28}[rtype]
    return [a["data"] for a in data.get("Answer", []) if a.get("type") == want]


async def check(token: str, domain: str = "", target_ip: str = "") -> dict:
    out: dict = {"token_ok": False, "zones": [], "zone": None, "records": [], "ssl_mode": None,
                 "resolved": [], "proxied_live": None, "points_to_target": None, "error": ""}
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(base_url=API, headers=headers, timeout=15) as client:
        try:
            verify = (await client.get("/user/tokens/verify")).json()
        except (httpx.HTTPError, ValueError):
            out["error"] = "api_unreachable"
            return out
        out["token_ok"] = bool(verify.get("success")) and verify.get("result", {}).get("status") == "active"
        if not out["token_ok"]:
            out["error"] = "token_invalid"
            return out
        zones = (await client.get("/zones", params={"per_page": 50})).json().get("result", []) or []
        out["zones"] = [{"name": z["name"], "status": z["status"]} for z in zones]
        if not domain:
            return out
        zone = zone_for(domain, zones)
        if not zone:
            out["error"] = "zone_not_in_token"
            return out
        out["zone"] = zone["name"]
        recs = (await client.get(f"/zones/{zone['id']}/dns_records", params={"name": domain})).json()
        out["records"] = [
            {"type": r["type"], "content": r["content"], "proxied": r.get("proxied", False), "ttl": r.get("ttl")}
            for r in recs.get("result", []) or []
        ]
        ssl = (await client.get(f"/zones/{zone['id']}/settings/ssl")).json()
        if ssl.get("success"):
            out["ssl_mode"] = ssl["result"]["value"]
    if domain:
        out["resolved"] = await resolve(domain)
        if out["resolved"]:
            out["proxied_live"] = all(is_cloudflare_ip(ip) for ip in out["resolved"])
        if target_ip:
            origin = [r["content"] for r in out["records"] if r["type"] in ("A", "AAAA")]
            out["points_to_target"] = target_ip in origin if origin else False
    return out
