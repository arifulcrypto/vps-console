"""Globalping (https://globalping.io): free probes worldwide, a few in China.

Without a token the limit is about 250 tests per hour per IP. A token from
the admin page raises it.
"""

from __future__ import annotations

import asyncio

import httpx

API = "https://api.globalping.io/v1/measurements"


async def measure(target: str, *, kind: str = "ping", country: str = "CN", limit: int = 3,
                  port: int | None = None, token: str = "", timeout: float = 45) -> dict:
    options: dict = {"packets": 3}
    if kind == "ping" and port:
        options.update({"protocol": "TCP", "port": port})
    body = {"type": kind, "target": target, "locations": [{"country": country, "limit": limit}],
            "measurementOptions": options}
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with httpx.AsyncClient(timeout=15, headers=headers) as client:
        try:
            resp = await client.post(API, json=body)
        except httpx.HTTPError:
            return {"ok": False, "error": "unreachable"}
        if resp.status_code == 422:
            return {"ok": False, "error": "no_probes"}
        if resp.status_code == 429:
            return {"ok": False, "error": "rate_limited"}
        if resp.status_code >= 400:
            return {"ok": False, "error": f"http_{resp.status_code}"}
        mid = resp.json().get("id")
        deadline = asyncio.get_running_loop().time() + timeout
        data: dict = {}
        while asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(1.5)
            try:
                data = (await client.get(f"{API}/{mid}")).json()
            except (httpx.HTTPError, ValueError):
                continue
            if data.get("status") != "in-progress":
                break
    return {"ok": True, "id": mid, "port": port, "results": [summarize(r) for r in data.get("results", [])]}


def summarize(item: dict) -> dict:
    probe = item.get("probe", {})
    result = item.get("result", {})
    stats = result.get("stats", {}) or {}
    return {
        "city": probe.get("city", ""),
        "country": probe.get("country", ""),
        "network": probe.get("network", ""),
        "asn": probe.get("asn"),
        "status": result.get("status", ""),
        "avg": stats.get("avg"),
        "loss": stats.get("loss"),
    }


def reachable(results: list[dict]) -> bool | None:
    """True if any probe got answers, False if all lost everything, None if no data."""
    usable = [r for r in results if r.get("loss") is not None]
    if not usable:
        return None
    return any(r["loss"] < 100 for r in usable)
