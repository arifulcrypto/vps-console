"""Return-route analysis: from the VPS back to the three Chinese carriers.

The trace runs on the target VPS itself (mtr if present, otherwise
traceroute). Line types come from AS numbers when mtr can resolve them,
and from well-known address prefixes otherwise.
"""

from __future__ import annotations

import asyncio
import re

from .ssh import run

# Carrier test addresses used by common backtrace tools.
CARRIER_TARGETS = [
    {"city": "Shanghai", "carrier": "telecom", "ip": "202.96.209.133"},
    {"city": "Shanghai", "carrier": "unicom", "ip": "210.22.97.1"},
    {"city": "Shanghai", "carrier": "mobile", "ip": "211.136.112.200"},
    {"city": "Beijing", "carrier": "telecom", "ip": "219.141.140.10"},
    {"city": "Beijing", "carrier": "unicom", "ip": "202.106.195.68"},
    {"city": "Beijing", "carrier": "mobile", "ip": "221.179.155.161"},
    {"city": "Guangzhou", "carrier": "telecom", "ip": "58.60.188.222"},
    {"city": "Guangzhou", "carrier": "unicom", "ip": "210.21.196.6"},
    {"city": "Guangzhou", "carrier": "mobile", "ip": "120.196.165.24"},
]

QUICK_CITIES = {"Shanghai"}

ASN_TAGS = {
    "AS4809": "CN2",
    "AS4134": "163",
    "AS4837": "4837",
    "AS9929": "9929",
    "AS10099": "CUG",
    "AS58807": "CMIN2",
    "AS58453": "CMI",
    "AS9808": "CMNET",
    "AS56040": "CMNET",
    "AS56041": "CMNET",
    "AS56046": "CMNET",
}
PREFIX_TAGS = [
    ("59.43.", "CN2"),
    ("202.97.", "163"),
    ("219.158.", "4837"),
    ("218.105.", "9929"),
    ("210.51.", "9929"),
    ("223.118.", "CMI"),
    ("223.119.", "CMI"),
    ("223.120.", "CMI"),
    ("223.121.", "CMI"),
    ("221.183.", "CMNET"),
    ("221.176.", "CMNET"),
    ("111.24.", "CMNET"),
]
TRANSIT_ASNS = {
    "AS174": "Cogent", "AS3356": "Lumen", "AS6939": "Hurricane Electric", "AS1299": "Arelion",
    "AS2914": "NTT", "AS3257": "GTT", "AS6461": "Zayo", "AS6453": "TATA", "AS3491": "PCCW",
}
NEAR_CHINA = {"JP", "HK", "SG", "KR", "TW", "MO", "MY", "TH", "VN", "PH"}

_MTR = re.compile(r"^\s*(\d+)\.\|?-*\s*(?:(AS[\d?]+)\s+)?(\S+)\s+([\d.]+)%\s+\d+\s+[\d.]+\s+([\d.]+)")
_TR = re.compile(r"^\s*(\d+)\s+(\S+)\s+([\d.]+)\s*ms")


def parse_mtr(text: str) -> list[dict]:
    hops = []
    for line in text.splitlines():
        m = _MTR.match(line)
        if not m:
            continue
        ip = m.group(3)
        hops.append({
            "n": int(m.group(1)),
            "asn": (m.group(2) or "").replace("AS???", ""),
            "ip": "" if ip == "???" else ip,
            "loss": float(m.group(4)),
            "rtt": float(m.group(5)) if ip != "???" else None,
        })
    return hops


def parse_traceroute(text: str) -> list[dict]:
    hops = []
    for line in text.splitlines():
        m = _TR.match(line)
        if m:
            hops.append({"n": int(m.group(1)), "asn": "", "ip": m.group(2), "loss": 0.0, "rtt": float(m.group(3))})
        elif re.match(r"^\s*\d+\s+\*", line):
            hops.append({"n": int(line.split()[0]), "asn": "", "ip": "", "loss": 100.0, "rtt": None})
    return hops


def tags_of(hop: dict) -> set[str]:
    tags = set()
    if hop.get("asn") in ASN_TAGS:
        tags.add(ASN_TAGS[hop["asn"]])
    for prefix, tag in PREFIX_TAGS:
        if hop.get("ip", "").startswith(prefix):
            tags.add(tag)
    return tags


def classify(hops: list[dict], carrier: str, country_code: str = "") -> dict:
    tags: set[str] = set()
    transit = []
    for hop in hops:
        tags |= tags_of(hop)
        name = TRANSIT_ASNS.get(hop.get("asn", ""))
        if name and name not in transit:
            transit.append(name)
    if "CN2" in tags:
        line = "CN2 GT" if "163" in tags else "CN2 GIA"
    elif "9929" in tags or "CUG" in tags:
        line = "CU 9929"
    elif "CMIN2" in tags:
        line = "CMIN2"
    elif "163" in tags:
        line = "163"
    elif "4837" in tags:
        line = "CU 4837"
    elif "CMI" in tags:
        line = "CMI"
    elif "CMNET" in tags:
        line = "CMNET"
    else:
        line = "unknown"
    premium = line in ("CN2 GIA", "CU 9929", "CMIN2")
    rtts = [h["rtt"] for h in hops if h.get("rtt") is not None]
    final = rtts[-1] if rtts else None
    detour = bool(final and country_code in NEAR_CHINA and final > 150)
    return {
        "carrier": carrier,
        "line": line,
        "premium": premium,
        "rtt": final,
        "detour": detour,
        "transit": transit,
        "hops": hops[-30:],
    }


TRACE_CMD = (
    "export PATH=$PATH:/usr/sbin:/sbin; "
    "if command -v mtr >/dev/null; then echo MTR; mtr -n -z -r -w -c 3 {ip} 2>&1; "
    "elif command -v traceroute >/dev/null; then echo TR; traceroute -n -q 1 -w 2 -m 30 {ip} 2>&1; "
    "else echo NONE; fi"
)


async def trace_from(conn, targets: list[dict], country_code: str = "") -> list[dict]:
    async def one(t: dict) -> dict:
        res = await run(conn, TRACE_CMD.format(ip=t["ip"]), timeout=90)
        out = res.stdout
        if out.startswith("MTR"):
            hops = parse_mtr(out)
        elif out.startswith("TR"):
            hops = parse_traceroute(out)
        else:
            return {**t, "line": "no_tool", "hops": [], "rtt": None, "premium": False, "detour": False,
                    "transit": []}
        return {**t, **classify(hops, t["carrier"], country_code)}

    return list(await asyncio.gather(*(one(t) for t in targets)))


def pick_targets(mode: str) -> list[dict]:
    if mode == "deep":
        return CARRIER_TARGETS
    return [t for t in CARRIER_TARGETS if t["city"] in QUICK_CITIES]
