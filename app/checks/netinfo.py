"""IP region and network type, via ip-api.com (free, no key, 45 requests/min)."""

from __future__ import annotations

import ipaddress

import httpx

FIELDS = "status,message,country,countryCode,regionName,city,isp,org,as,asname,mobile,proxy,hosting,query"


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global


async def lookup(ip: str, client: httpx.AsyncClient | None = None) -> dict:
    own = client is None
    client = client or httpx.AsyncClient(timeout=10)
    try:
        resp = await client.get(f"http://ip-api.com/json/{ip}", params={"fields": FIELDS})
        data = resp.json()
    except (httpx.HTTPError, ValueError):
        return {"ok": False, "ip": ip}
    finally:
        if own:
            await client.aclose()
    if data.get("status") != "success":
        return {"ok": False, "ip": ip, "error": data.get("message", "")}
    return {
        "ok": True,
        "ip": data.get("query", ip),
        "country": data.get("country", ""),
        "country_code": data.get("countryCode", ""),
        "region": data.get("regionName", ""),
        "city": data.get("city", ""),
        "isp": data.get("isp", ""),
        "org": data.get("org", ""),
        "asn": (data.get("as") or "").split(" ")[0],
        "as_name": data.get("asname", ""),
        "mobile": bool(data.get("mobile")),
        "proxy": bool(data.get("proxy")),
        "hosting": bool(data.get("hosting")),
        "kind": classify_kind(data),
    }


def classify_kind(data: dict) -> str:
    """Rough IP type. ip-api flags are a hint, not proof."""
    if data.get("mobile"):
        return "mobile"
    if data.get("hosting"):
        return "datacenter"
    if data.get("proxy"):
        return "proxy_flagged"
    return "isp"
