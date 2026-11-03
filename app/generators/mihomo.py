"""Build a full Mihomo config from proxies, with the converter's options.

Group layout and DNS follow vps-deploy-skill's clash_generator.py so both
produce the same behaviour: metered residential/relay nodes are never in
url-test groups, Chinese domains resolve at home, the rest via the proxy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import yaml

PROBE_URL = "https://www.gstatic.com/generate_204"
CN_DNS = ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"]
REMOTE_DNS = ["https://1.1.1.1/dns-query", "https://dns.google/dns-query"]
GEO_BASE = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release"

REGIONS = [
    ("HK", "🇭🇰", r"港|HK|Hong ?Kong"),
    ("TW", "🇹🇼", r"台|TW|Taiwan"),
    ("JP", "🇯🇵", r"日本|JP|Japan|Tokyo|Osaka|东京|大阪"),
    ("SG", "🇸🇬", r"新加坡|狮城|SG|Singapore"),
    ("KR", "🇰🇷", r"韩|KR|Korea|Seoul"),
    ("US", "🇺🇸", r"美|US|United States|America|Los Angeles|San Jose|洛杉矶|圣何塞"),
    ("GB", "🇬🇧", r"英|UK|GB|London|United Kingdom"),
    ("DE", "🇩🇪", r"德|DE|Germany|Frankfurt"),
]

NAMES = {
    "en": {"main": "🚀 Proxy", "auto": "⚡ Auto (latency)", "fallback": "🛟 Failover",
           "relay": "🏠 Residential & Relay", "ai": "🤖 AI Services", "tk": "🛒 E-Commerce & TikTok",
           "media": "🎬 Streaming", "tg": "📲 Telegram", "ads": "🛑 Ads", "final": "🐟 Everything else"},
    "zh": {"main": "🚀 节点选择", "auto": "⚡ 自动选择 (低延迟)", "fallback": "🛟 故障转移",
           "relay": "🏠 住宅与家宽专线", "ai": "🤖 AI与ChatGPT", "tk": "🛒 外贸与TikTok",
           "media": "🎬 流媒体", "tg": "📲 Telegram", "ads": "🛑 广告拦截", "final": "🐟 漏网之鱼"},
}


@dataclass
class ConvertOptions:
    include: str = ""
    exclude: str = ""
    renames: list[tuple[str, str]] = field(default_factory=list)
    prefix: str = ""
    add_flags: bool = False
    dedupe: bool = True
    sort: bool = False
    residential_pattern: str = r"住宅|家宽|residential|resi|isp|relay|中转"
    groups: str = "full"  # full | simple | region
    china_direct: bool = True
    block_ads: bool = False
    ai_group: bool = True
    streaming_group: bool = False
    telegram_group: bool = False
    fake_ip: bool = True
    ipv6: bool = False
    mixed_port: int = 7890
    allow_lan: bool = False
    lang: str = "en"


def _regex(pattern: str) -> re.Pattern | None:
    if not pattern:
        return None
    try:
        return re.compile(pattern, re.I)
    except re.error as exc:
        raise ValueError(f"bad pattern {pattern!r}: {exc}") from exc


def region_of(name: str) -> tuple[str, str] | None:
    for code, flag, pattern in REGIONS:
        if re.search(pattern, name, re.I):
            return code, flag
    return None


def transform(proxies: list[dict], opts: ConvertOptions) -> list[dict]:
    inc, exc = _regex(opts.include), _regex(opts.exclude)
    renames = [(_regex(a), b) for a, b in opts.renames if a]
    out: list[dict] = []
    seen_keys: set[tuple] = set()
    seen_names: dict[str, int] = {}
    for original in proxies:
        p = dict(original)
        name = str(p.get("name", ""))
        if inc and not inc.search(name):
            continue
        if exc and exc.search(name):
            continue
        key = (p.get("type"), p.get("server"), p.get("port"), p.get("uuid") or p.get("password"))
        if opts.dedupe and key in seen_keys:
            continue
        seen_keys.add(key)
        for rx, repl in renames:
            name = rx.sub(repl, name)
        if opts.add_flags:
            region = region_of(name)
            if region and not name.startswith(region[1]):
                name = f"{region[1]} {name}"
        name = f"{opts.prefix}{name}".strip() or f"{p.get('type')}-{p.get('server')}"
        if name in seen_names:  # Mihomo needs unique names
            seen_names[name] += 1
            name = f"{name} {seen_names[name]}"
        else:
            seen_names[name] = 1
        p["name"] = name
        out.append(p)
    if opts.sort:
        out.sort(key=lambda x: x["name"])
    return out


def build_config(proxies: list[dict], opts: ConvertOptions) -> dict:
    g = NAMES.get(opts.lang, NAMES["en"])
    resi_rx = _regex(opts.residential_pattern)
    names = [p["name"] for p in proxies]
    metered = [n for n in names if resi_rx and resi_rx.search(n)]
    datacenter = [n for n in names if n not in metered]

    groups: list[dict] = []
    main = []
    if datacenter:
        main += [g["auto"], g["fallback"]]
    if metered:
        main.append(g["relay"])
    region_groups: list[dict] = []
    if opts.groups == "region":
        for code, flag, _ in REGIONS:
            members = [n for n in datacenter if region_of(n) and region_of(n)[0] == code]
            if members:
                region_groups.append({"name": f"{flag} {code}", "type": "url-test", "url": PROBE_URL,
                                      "interval": 300, "tolerance": 50, "proxies": members})
        main += [rg["name"] for rg in region_groups]
    main += names + ["DIRECT"]
    groups.append({"name": g["main"], "type": "select", "proxies": main})
    if datacenter:
        groups.append({"name": g["auto"], "type": "url-test", "url": PROBE_URL, "interval": 300,
                       "tolerance": 50, "proxies": datacenter})
        groups.append({"name": g["fallback"], "type": "fallback", "url": PROBE_URL, "interval": 300,
                       "proxies": datacenter})
    groups += region_groups
    if metered:
        groups.append({"name": g["relay"], "type": "select", "proxies": metered + ["DIRECT"]})

    rules = [
        "DOMAIN-SUFFIX,local,DIRECT",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
        "IP-CIDR,198.18.0.0/16,DIRECT,no-resolve",
    ]
    if opts.groups != "simple":
        if opts.block_ads:
            groups.append({"name": g["ads"], "type": "select", "proxies": ["REJECT", "DIRECT"]})
            rules.append(f"GEOSITE,category-ads-all,{g['ads']}")
        if opts.ai_group:
            ai = ([g["relay"]] + metered if metered else []) + [g["main"]] + datacenter
            groups.append({"name": g["ai"], "type": "select", "proxies": ai})
            rules += [f"GEOSITE,openai,{g['ai']}", f"GEOSITE,anthropic,{g['ai']}",
                      f"DOMAIN-SUFFIX,claude.ai,{g['ai']}", f"DOMAIN-SUFFIX,gemini.google.com,{g['ai']}"]
        tk = ([g["relay"]] + metered if metered else []) + [g["main"]] + datacenter
        groups.append({"name": g["tk"], "type": "select", "proxies": tk})
        rules += [f"GEOSITE,tiktok,{g['tk']}", f"DOMAIN-SUFFIX,paypal.com,{g['tk']}",
                  f"DOMAIN-SUFFIX,stripe.com,{g['tk']}"]
        if opts.streaming_group:
            groups.append({"name": g["media"], "type": "select", "proxies": [g["main"]] + names})
            rules += [f"GEOSITE,youtube,{g['media']}", f"GEOSITE,netflix,{g['media']}",
                      f"GEOSITE,disney,{g['media']}"]
        if opts.telegram_group:
            groups.append({"name": g["tg"], "type": "select", "proxies": [g["main"]] + names})
            rules += [f"GEOSITE,telegram,{g['tg']}", f"GEOIP,telegram,{g['tg']},no-resolve"]
    if opts.china_direct:
        rules += ["GEOSITE,private,DIRECT", "GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT,no-resolve"]
    rules.append(f"MATCH,{g['main']}")

    dns: dict = {
        "enable": True,
        "ipv6": opts.ipv6,
        "default-nameserver": ["223.5.5.5", "119.29.29.29"],
        "enhanced-mode": "fake-ip" if opts.fake_ip else "redir-host",
        "respect-rules": True,
        "nameserver": REMOTE_DNS,
        "proxy-server-nameserver": CN_DNS,
        "nameserver-policy": {"geosite:cn,private": CN_DNS},
    }
    if opts.fake_ip:
        dns["fake-ip-range"] = "198.18.0.1/16"
        dns["fake-ip-filter"] = ["*.lan", "*.local", "+.msftconnecttest.com", "+.msftncsi.com",
                                 "time.*.com", "ntp.*.com"]
    return {
        "mixed-port": opts.mixed_port,
        "allow-lan": opts.allow_lan,
        "bind-address": "*" if opts.allow_lan else "127.0.0.1",
        "mode": "rule",
        "log-level": "info",
        "ipv6": opts.ipv6,
        "unified-delay": True,
        "tcp-concurrent": True,
        "find-process-mode": "off",
        "geodata-loader": "memconservative",
        "geo-auto-update": True,
        "geo-update-interval": 168,
        "geox-url": {"geoip": f"{GEO_BASE}/geoip.dat", "geosite": f"{GEO_BASE}/geosite.dat",
                     "mmdb": f"{GEO_BASE}/country-lite.mmdb"},
        "external-controller": "127.0.0.1:9090",
        "sniffer": {"enable": True, "sniff": {"HTTP": {"ports": [80, "8080-8880"]},
                                              "TLS": {"ports": [443, 8443]}, "QUIC": {"ports": [443, 8443]}}},
        "dns": dns,
        "proxies": proxies,
        "proxy-groups": groups,
        "rules": rules,
    }


def dump(config: dict) -> str:
    return yaml.safe_dump(config, allow_unicode=True, sort_keys=False, width=1000)


def check_config(config: dict) -> list[str]:
    """Static checks Mihomo would fail on: duplicate names and unknown references."""
    problems = []
    names = [p["name"] for p in config.get("proxies", [])]
    if len(names) != len(set(names)):
        problems.append("duplicate proxy names")
    known = set(names) | {g["name"] for g in config.get("proxy-groups", [])} | {"DIRECT", "REJECT"}
    for group in config.get("proxy-groups", []):
        for member in group.get("proxies", []):
            if member not in known:
                problems.append(f"group {group['name']} references unknown {member}")
        if not group.get("proxies"):
            problems.append(f"group {group['name']} is empty")
    for rule in config.get("rules", []):
        target = rule.split(",")[2] if rule.count(",") >= 2 else rule.split(",")[-1]
        if rule.startswith("MATCH"):
            target = rule.split(",")[1]
        if target not in known:
            problems.append(f"rule {rule} targets unknown {target}")
    return problems
