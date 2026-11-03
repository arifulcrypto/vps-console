"""Markdown report of a check, for download. English only, for pasting into tools."""

from __future__ import annotations

import datetime as dt

from .i18n import translate


def _ts(value) -> str:
    return dt.datetime.fromtimestamp(float(value), dt.UTC).strftime("%Y-%m-%d %H:%M UTC") if value else ""


def to_markdown(job: dict) -> str:
    r = job.get("result", {})
    lines = [f"# Check: {job['target']} ({job['mode']})", "", f"Run: {_ts(job['created_at'])}", ""]
    ssh = r.get("ssh")
    if ssh:
        lines.append(f"SSH: {'ok' if ssh.get('ok') else 'failed (' + ssh.get('code', '') + ')'}")
    facts = r.get("facts")
    if facts:
        mem = facts["mem"]["total"] / 1024**3
        lines += [
            "", "## System",
            f"- OS: {facts['os']['pretty_name']}, kernel {facts['kernel']} ({facts['arch']})",
            f"- Virtualization: {facts['virt']}",
            f"- CPU: {facts['cpu']['count']} × {facts['cpu']['model']}",
            f"- RAM: {mem:.1f} GB, available {facts['mem']['available'] / 1024**2:.0f} MB",
            f"- Swap: {facts['swap']['total'] / 1024**3:.1f} GB, swappiness {facts['swappiness']}",
            f"- Disk: {facts['disk']['avail'] / 1024**3:.1f} GB free of {facts['disk']['total'] / 1024**3:.1f} GB",
            f"- TCP congestion control: {facts['net']['cc']} / {facts['net']['qdisc']}",
        ]
        if facts.get("versions"):
            lines.append("- Software: " + ", ".join(f"{k} {v}" for k, v in facts["versions"].items()))
        public = [f"{i['port']}/{i['proto']} {i['process']}" for i in facts["listeners"] if i["public"]]
        if public:
            lines.append("- Public listeners: " + ", ".join(public))
    if r.get("findings"):
        lines += ["", "## Findings"]
        for f in r["findings"]:
            lines.append(f"- [{f['level']}] {translate('en', 'f.' + f['code'], **f.get('params', {}))}")
    info = r.get("ipinfo")
    if info and info.get("ok"):
        lines += ["", "## IP", f"- {info['ip']}: {info['city']}, {info['country']} · {info['asn']} {info['isp']}"
                  f" · type {info['kind']}"]
    if r.get("routes"):
        lines += ["", "## Return routes to China", "| City | Carrier | Line | RTT |", "| --- | --- | --- | --- |"]
        for t in r["routes"]:
            rtt = f"{t['rtt']:.0f} ms" if t.get("rtt") else "-"
            lines.append(f"| {t['city']} | {t['carrier']} | {t['line']}{' (detour?)' if t.get('detour') else ''}"
                         f" | {rtt} |")
    rc = r.get("reach")
    if rc:
        lines += ["", "## Reachability", f"- Verdict: **{rc.get('verdict')}** {', '.join(rc.get('ports', []))}"]
        for side in ("abroad", "china"):
            data = rc.get(side)
            if data:
                ports = ", ".join(f"{p}:{'ok' if ms is not None else 'fail'}" for p, ms in data["ports"].items())
                lines.append(f"- {side}: ICMP {data['icmp'].get('ok')}, TCP {ports}, TLS {data.get('tls', {})}")
    cf = r.get("cloudflare")
    if cf:
        lines += ["", "## Cloudflare", f"- Token valid: {cf['token_ok']}, zone: {cf.get('zone')}, "
                  f"SSL mode: {cf.get('ssl_mode') or 'not readable'}"]
        for rec in cf.get("records", []):
            lines.append(f"- {rec['type']} → {rec['content']} (proxied: {rec['proxied']})")
    for p in r.get("proxies", []):
        if p.get("ok"):
            i = p["info"]
            lines.append(f"- Proxy {p['proxy']}: exit {p['exit_ips'][-1]} {i.get('country', '')} {i.get('isp', '')}"
                         f" type {i.get('kind', '?')}, sticky {p['sticky']}")
        else:
            lines.append(f"- Proxy {p['proxy']}: failed ({p.get('error')})")
    return "\n".join(lines) + "\n"
