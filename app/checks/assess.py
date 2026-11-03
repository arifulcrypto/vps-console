"""Turn raw facts into findings. Each finding is translated in the template
from its code, so both languages stay in step."""

from __future__ import annotations

import datetime as dt
import json
from functools import lru_cache
from pathlib import Path

GB = 1024**3
MB = 1024**2

# Ports the deploy skill wants: 80 for HTTP-01 certificates, 443 for REALITY
# or the CDN node, 2096 for the panel subscription.
SKILL_PORTS = {80: "http01", 443: "https", 2096: "sub"}

LEGACY_HINTS = {
    "/etc/caddy/233boy": "233boy script (Caddy + Xray/V2Ray)",
    "/etc/v2ray": "V2Ray",
    "/etc/xray": "standalone Xray",
    "/usr/local/etc/xray": "Xray official installer",
    "/etc/sing-box": "sing-box",
    "/etc/hysteria": "Hysteria",
    "/usr/local/x-ui": "3X-UI / x-ui panel",
    "/etc/realm": "Realm relay",
}


@lru_cache
def software() -> dict:
    return json.loads((Path(__file__).resolve().parent.parent / "data" / "software.json").read_text())


def vtuple(version: str) -> tuple[int, ...]:
    out = []
    for part in version.lstrip("v").split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out)


def finding(level: str, code: str, **params) -> dict:
    return {"level": level, "code": code, "params": params}


def os_status(os_info: dict, today: dt.date | None = None) -> dict:
    today = today or dt.date.today()
    key = f"{os_info.get('id', '')} {os_info.get('version_id', '')}".strip().lower()
    entry = software()["os"].get(key)
    if not entry:
        return finding("info", "os_unknown", name=os_info.get("pretty_name", "?"))
    end = dt.date.fromisoformat(entry["end"])
    days = (end - today).days
    if days < 0:
        return finding("bad", "os_ended", name=os_info["pretty_name"], end=entry["end"])
    if days < 365:
        return finding("warn", "os_ending", name=os_info["pretty_name"], end=entry["end"])
    if entry["rank"] == "best":
        return finding("ok", "os_best", name=os_info["pretty_name"], end=entry["end"])
    return finding("info", "os_ok", name=os_info["pretty_name"], end=entry["end"])


def lxd_plan(facts: dict) -> dict:
    """Is LXD possible here, and how many containers fit."""
    virt = facts.get("virt", "unknown")
    container = facts.get("container", "none")
    if container not in ("none", "") or virt in ("openvz", "lxc", "lxc-libvirt", "docker", "podman", "wsl"):
        return {"possible": False, "reason": "container_vps", "containers": 0}
    ram_gb = facts["mem"]["total"] / GB
    disk_gb = (facts["disk"]["avail"]) / GB
    cpu = facts["cpu"]["count"]
    if ram_gb < 0.9 or disk_gb < 8:
        return {"possible": False, "reason": "too_small", "containers": 0}
    by_ram = 4 if ram_gb >= 3.5 else 2 if ram_gb >= 1.8 else 1
    by_disk = max(1, int(disk_gb // 7))
    by_cpu = 4 if cpu >= 2 else 2
    count = max(1, min(by_ram, by_disk, by_cpu))
    mem_each = int((facts["mem"]["total"] / MB - 600) / count) // 128 * 128
    return {"possible": True, "reason": "", "containers": count, "memory_mb_each": max(384, mem_each)}


def assess(facts: dict, today: dt.date | None = None) -> list[dict]:
    out: list[dict] = [os_status(facts["os"], today)]

    # Virtualization and LXD
    plan = lxd_plan(facts)
    if plan["possible"]:
        out.append(finding("ok", "lxd_possible", virt=facts["virt"], containers=plan["containers"],
                           memory=plan["memory_mb_each"]))
    elif plan["reason"] == "container_vps":
        out.append(finding("bad", "lxd_container_vps", virt=facts["virt"]))
    else:
        out.append(finding("warn", "lxd_too_small"))

    kernel = vtuple(facts.get("kernel", "0"))
    if kernel and kernel < (5, 15):
        out.append(finding("info", "kernel_old", kernel=facts["kernel"]))

    # Memory, swap, disk
    mem = facts["mem"]
    if mem["total"] and mem["available"] / mem["total"] < 0.15:
        out.append(finding("warn", "mem_low", avail=round(mem["available"] / MB)))
    swap_total = facts["swap"]["total"]
    if swap_total == 0 and mem["total"] <= 4.5 * GB:
        out.append(finding("warn", "swap_none"))
    elif swap_total > 2 * mem["total"]:
        out.append(finding("info", "swap_large", swap=round(swap_total / GB, 1)))
    else:
        out.append(finding("ok", "swap_ok", swap=round(swap_total / GB, 1)))
    if facts.get("swappiness", -1) > 30 and swap_total:
        out.append(finding("info", "swappiness_high", value=facts["swappiness"]))
    disk = facts["disk"]
    if disk["total"]:
        used_pct = round(disk["used"] * 100 / disk["total"])
        if disk["avail"] < 5 * GB:
            out.append(finding("bad", "disk_full", avail=round(disk["avail"] / GB, 1), pct=used_pct))
        elif used_pct > 85:
            out.append(finding("warn", "disk_high", pct=used_pct))

    # Network tuning
    net = facts["net"]
    if net.get("cc") == "bbr":
        out.append(finding("ok", "bbr_on"))
    elif "bbr" in net.get("available_cc", []):
        out.append(finding("warn", "bbr_off", cc=net.get("cc", "?")))
    else:
        out.append(finding("warn", "bbr_missing", cc=net.get("cc", "?")))

    # Ports the deploy skill needs
    public = [item for item in facts["listeners"] if item["public"]]
    for port, purpose in SKILL_PORTS.items():
        users = sorted({i["process"] or "?" for i in public if i["port"] == port and i["proto"] == "tcp"})
        if users:
            out.append(finding("warn", f"port_{purpose}_busy", port=port, process=", ".join(users)))

    # Existing proxy stacks and web servers
    for path in facts.get("legacy_paths", []):
        if path in LEGACY_HINTS:
            out.append(finding("info", "legacy_found", what=LEGACY_HINTS[path], path=path))
    if "/etc/vps-skill" in facts.get("legacy_paths", []):
        out.append(finding("info", "skill_present"))
    services = facts.get("services", {})
    for fw in ("ufw", "firewalld"):
        if services.get(fw, {}).get("active") == "active":
            out.append(finding("info", "firewall_active", name=fw))

    # Versions against what the skills tested
    versions = facts.get("versions", {})
    server = software()["server"]
    for name in ("xray", "x-ui", "lxd", "sing-box", "realm"):
        if name not in versions:
            continue
        have, tested = versions[name], server[name]["tested"]
        if vtuple(have) < vtuple(tested):
            out.append(finding("warn", "version_old", name=name, have=have, tested=tested, url=server[name]["url"]))
        elif vtuple(have) > vtuple(tested):
            out.append(finding("info", "version_newer", name=name, have=have, tested=tested))
        else:
            out.append(finding("ok", "version_tested", name=name, have=have))
    if facts.get("boot_status"):
        level = "ok" if facts["boot_status"].startswith("OK") else "warn"
        out.append(finding(level, "boot_status", status=facts["boot_status"].splitlines()[0][:120]))
    return out


def score(findings: list[dict]) -> str:
    levels = {f["level"] for f in findings}
    if "bad" in levels:
        return "bad"
    if "warn" in levels:
        return "warn"
    return "ok"
