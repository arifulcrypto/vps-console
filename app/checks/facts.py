"""Collect system facts from a target in one SSH round trip and parse them.

The script is read-only: it lists, reads and prints. It never installs,
starts, stops or edits anything.
"""

from __future__ import annotations

import re

FACTS_SCRIPT = r"""
export LC_ALL=C PATH="$PATH:/usr/local/bin:/usr/local/sbin:/usr/sbin:/sbin:/snap/bin"
sec(){ echo "@@$1"; }
v(){ k="$1"; shift; printf '%s=%s\n' "$k" "$("$@" 2>&1 | head -n1)"; }
sec os; cat /etc/os-release 2>/dev/null
sec kernel; uname -r; uname -m
sec virt; systemd-detect-virt 2>/dev/null || echo unknown
sec container; systemd-detect-virt -c 2>/dev/null || echo none
sec cpu; nproc; grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2-
sec mem; free -b
sec swap; swapon --show=NAME,SIZE,USED --bytes --noheadings 2>/dev/null
sec swappiness; sysctl -n vm.swappiness 2>/dev/null
sec disk; df -B1 --output=size,used,avail / 2>/dev/null | tail -n1
sec uptime; cut -d' ' -f1 /proc/uptime; cut -d' ' -f1-3 /proc/loadavg
sec net; sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null; sysctl -n net.core.default_qdisc 2>/dev/null; sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null
sec ip; ip -o addr show scope global 2>/dev/null | awk '{print $2, $3, $4}'
sec listen; ss -H -ltnup 2>/dev/null
sec services
for s in x-ui xray v2ray sing-box hysteria-server nginx caddy apache2 httpd docker snap.lxd.daemon incus realm ufw firewalld fail2ban vps-skill-bootcheck.timer vps-lxc-bootcheck.timer; do
  printf '%s %s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null)" "$(systemctl is-enabled "$s" 2>/dev/null)"
done
sec versions
for x in /usr/local/x-ui/bin/xray-linux-*; do [ -x "$x" ] && v xray_xui "$x" version; done
command -v xray >/dev/null && v xray xray version
[ -x /usr/local/x-ui/x-ui ] && v x-ui /usr/local/x-ui/x-ui -v
command -v nginx >/dev/null && v nginx nginx -v
command -v caddy >/dev/null && v caddy caddy version
command -v sing-box >/dev/null && v sing-box sing-box version
command -v lxd >/dev/null && v lxd lxd --version
command -v incus >/dev/null && v incus incus --version
command -v docker >/dev/null && v docker docker --version
command -v realm >/dev/null && v realm realm --version
command -v python3 >/dev/null && v python3 python3 --version
command -v snap >/dev/null && echo "snap=yes"
[ -x /root/.acme.sh/acme.sh ] && echo "acme.sh=installed"
sec legacy
for d in /etc/v2ray /etc/xray /usr/local/etc/xray /etc/caddy/233boy /usr/local/x-ui /etc/x-ui /etc/sing-box /etc/hysteria /etc/vps-skill /var/lib/vps-lxc /etc/realm; do
  [ -e "$d" ] && echo "$d"
done
sec bootstatus; cat /var/lib/vps-skill/boot-status 2>/dev/null | head -n3
sec kvm; [ -e /dev/kvm ] && echo yes || echo no
"""

_SECTION = re.compile(r"^@@([a-z_]+)\s*$", re.M)
_VERSION = re.compile(r"v?(\d+(?:\.\d+){1,3})")


def split_sections(output: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    matches = list(_SECTION.finditer(output))
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(output)
        sections[m.group(1)] = output[m.end():end].strip("\n")
    return sections


def _lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip()]


def _int(value: str, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def parse_os_release(text: str) -> dict[str, str]:
    data = {}
    for line in _lines(text):
        if "=" in line:
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip().strip('"')
    return {
        "id": data.get("ID", "unknown"),
        "version_id": data.get("VERSION_ID", ""),
        "pretty_name": data.get("PRETTY_NAME", "unknown"),
        "codename": data.get("VERSION_CODENAME", ""),
    }


def parse_free(text: str) -> dict[str, int]:
    for line in _lines(text):
        parts = line.split()
        if parts and parts[0] == "Mem:" and len(parts) >= 7:
            total, used, free, shared, cache, available = (_int(p) for p in parts[1:7])
            return {"total": total, "used": used, "free": free, "cache": cache, "available": available}
    return {"total": 0, "used": 0, "free": 0, "cache": 0, "available": 0}


def parse_swap(text: str) -> dict[str, int]:
    total = used = 0
    for line in _lines(text):
        parts = line.split()
        if len(parts) >= 3:
            total += _int(parts[1])
            used += _int(parts[2])
    return {"total": total, "used": used}


def parse_listeners(text: str) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple] = set()
    for line in _lines(text):
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        local = parts[4]
        if ":" not in local:
            continue
        addr, port = local.rsplit(":", 1)
        if not port.isdigit():
            continue
        proc = re.search(r'\(\("([^"]+)"', line)
        addr = addr.strip("[]").split("%")[0]
        item = (proto, addr, int(port))
        if item in seen:
            continue
        seen.add(item)
        out.append({
            "proto": proto,
            "addr": addr,
            "port": int(port),
            "process": proc.group(1) if proc else "",
            "public": addr not in ("127.0.0.1", "::1", "127.0.0.53", "127.0.0.54"),
        })
    out.sort(key=lambda x: (x["port"], x["proto"]))
    return out


def parse_services(text: str) -> dict[str, dict[str, str]]:
    services = {}
    for line in _lines(text):
        parts = line.split()
        if not parts:
            continue
        name = parts[0]
        active = parts[1] if len(parts) > 1 else "unknown"
        enabled = parts[2] if len(parts) > 2 else ""
        if active in ("inactive", "unknown") and enabled in ("", "not-found"):
            continue
        services[name] = {"active": active, "enabled": enabled}
    return services


def parse_versions(text: str) -> dict[str, str]:
    raw: dict[str, str] = {}
    for line in _lines(text):
        if "=" in line:
            k, v = line.split("=", 1)
            raw[k.strip()] = v.strip()
    versions: dict[str, str] = {}
    for key, value in raw.items():
        if key in ("snap", "acme.sh"):
            versions[key] = value
            continue
        m = _VERSION.search(value)
        if m and "not found" not in value.lower():
            versions[key] = m.group(1)
    # The panel's bundled Xray is the one that runs; prefer it.
    if "xray_xui" in versions:
        versions["xray"] = versions.pop("xray_xui")
    return versions


def parse_ips(text: str) -> dict[str, list[str]]:
    v4, v6 = [], []
    for line in _lines(text):
        parts = line.split()
        if len(parts) < 3 or parts[0].startswith(("docker", "br-", "veth", "lxdbr", "lo")):
            continue
        ip = parts[2].split("/")[0]
        (v6 if parts[1] == "inet6" else v4).append(ip)
    return {"ipv4": v4, "ipv6": v6}


def parse_facts(output: str) -> dict:
    s = split_sections(output)
    kernel_lines = _lines(s.get("kernel", ""))
    cpu_lines = _lines(s.get("cpu", ""))
    disk = [_int(p) for p in s.get("disk", "").split()] + [0, 0, 0]
    uptime_lines = _lines(s.get("uptime", ""))
    net = _lines(s.get("net", ""))
    return {
        "os": parse_os_release(s.get("os", "")),
        "kernel": kernel_lines[0] if kernel_lines else "",
        "arch": kernel_lines[1] if len(kernel_lines) > 1 else "",
        "virt": (s.get("virt", "unknown").strip() or "unknown"),
        "container": (s.get("container", "none").strip() or "none"),
        "cpu": {
            "count": _int(cpu_lines[0]) if cpu_lines else 0,
            "model": cpu_lines[1].strip() if len(cpu_lines) > 1 else "",
        },
        "mem": parse_free(s.get("mem", "")),
        "swap": parse_swap(s.get("swap", "")),
        "swappiness": _int(s.get("swappiness", ""), -1),
        "disk": {"total": disk[0], "used": disk[1], "avail": disk[2]},
        "uptime_s": _int(uptime_lines[0]) if uptime_lines else 0,
        "load": uptime_lines[1] if len(uptime_lines) > 1 else "",
        "net": {
            "cc": net[0] if net else "",
            "qdisc": net[1] if len(net) > 1 else "",
            "available_cc": net[2].split() if len(net) > 2 else [],
        },
        "ips": parse_ips(s.get("ip", "")),
        "listeners": parse_listeners(s.get("listen", "")),
        "services": parse_services(s.get("services", "")),
        "versions": parse_versions(s.get("versions", "")),
        "legacy_paths": _lines(s.get("legacy", "")),
        "boot_status": s.get("bootstatus", "").strip(),
        "kvm_device": s.get("kvm", "").strip() == "yes",
    }
