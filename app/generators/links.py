"""Share links <-> Mihomo proxy dicts.

Supported: vless, vmess, trojan, ss, hysteria2/hy2, tuic, socks5.
Unknown or broken lines are reported, never silently dropped.
"""

from __future__ import annotations

import base64
import json
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit

import yaml


def _b64decode(data: str) -> str:
    data = data.strip().replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data).decode("utf-8", errors="replace")


def _q(params: dict, key: str, default: str = "") -> str:
    return params.get(key, [default])[0]


def _truthy(value: str) -> bool:
    return value.lower() in ("1", "true", "yes")


def _transport(proxy: dict, params: dict, host_header: str = "") -> None:
    net = _q(params, "type", "tcp") or "tcp"
    if net in ("tcp", "raw", "none"):
        return
    path = unquote(_q(params, "path", "/")) or "/"
    host = _q(params, "host", host_header)
    if net == "ws":
        proxy["network"] = "ws"
        opts: dict = {"path": path}
        if host:
            opts["headers"] = {"Host": host}
        proxy["ws-opts"] = opts
    elif net == "grpc":
        proxy["network"] = "grpc"
        proxy["grpc-opts"] = {"grpc-service-name": _q(params, "serviceName", "")}
    elif net == "xhttp":
        proxy["network"] = "xhttp"
        opts = {"path": path}
        if host:
            opts["host"] = host
        mode = _q(params, "mode", "")
        if mode:
            opts["mode"] = mode
        proxy["xhttp-opts"] = opts
    elif net in ("h2", "http"):
        proxy["network"] = "h2"
        proxy["h2-opts"] = {"path": path, **({"host": [host]} if host else {})}
    elif net == "httpupgrade":
        proxy["network"] = "ws"
        proxy["ws-opts"] = {"path": path, "v2ray-http-upgrade": True, **({"headers": {"Host": host}} if host else {})}
    else:
        raise ValueError(f"transport {net} not supported")


def _tls(proxy: dict, params: dict, mlkem: bool) -> None:
    security = _q(params, "security", "")
    sni = _q(params, "sni", "") or _q(params, "peer", "")
    if security in ("tls", "reality"):
        proxy["tls"] = True
        if sni:
            proxy["servername"] = sni
        fp = _q(params, "fp", "")
        if fp:
            proxy["client-fingerprint"] = fp
        alpn = _q(params, "alpn", "")
        if alpn:
            proxy["alpn"] = unquote(alpn).split(",")
        if _truthy(_q(params, "allowInsecure", "0")) or _truthy(_q(params, "insecure", "0")):
            proxy["skip-cert-verify"] = True
    if security == "reality":
        opts = {"public-key": _q(params, "pbk", ""), "short-id": _q(params, "sid", "")}
        if mlkem:
            opts["support-x25519mlkem768"] = True
        proxy["reality-opts"] = opts
        proxy.setdefault("client-fingerprint", "chrome")


def parse_link(line: str, mlkem: bool = True) -> dict:
    line = line.strip()
    scheme = line.split("://", 1)[0].lower()
    if scheme == "vmess":
        return _vmess(line)
    if scheme == "ss":
        return _ss(line)
    u = urlsplit(line)
    params = parse_qs(u.query)
    name = unquote(u.fragment) or f"{scheme}-{u.hostname}:{u.port}"
    if not u.hostname or not u.port:
        raise ValueError("missing server or port")
    base = {"name": name, "server": u.hostname, "port": u.port}
    if scheme == "vless":
        proxy = {**base, "type": "vless", "uuid": unquote(u.username or ""), "udp": True}
        flow = _q(params, "flow", "")
        if flow:
            proxy["flow"] = flow
        enc = _q(params, "encryption", "none")
        if enc and enc != "none":
            proxy["encryption"] = enc
        _tls(proxy, params, mlkem)
        _transport(proxy, params)
        return proxy
    if scheme == "trojan":
        proxy = {**base, "type": "trojan", "password": unquote(u.username or ""), "udp": True}
        sni = _q(params, "sni", "") or _q(params, "peer", "")
        if sni:
            proxy["sni"] = sni
        if _truthy(_q(params, "allowInsecure", "0")):
            proxy["skip-cert-verify"] = True
        fp = _q(params, "fp", "")
        if fp:
            proxy["client-fingerprint"] = fp
        _transport(proxy, params)
        return proxy
    if scheme in ("hysteria2", "hy2"):
        auth = unquote(u.username or "")
        if u.password:
            auth = f"{auth}:{unquote(u.password)}"
        proxy = {**base, "type": "hysteria2", "password": auth}
        sni = _q(params, "sni", "")
        if sni:
            proxy["sni"] = sni
        if _q(params, "obfs", ""):
            proxy["obfs"] = _q(params, "obfs")
            proxy["obfs-password"] = _q(params, "obfs-password", "")
        if _truthy(_q(params, "insecure", "0")):
            proxy["skip-cert-verify"] = True
        pin = _q(params, "pinSHA256", "")
        if pin:
            proxy["fingerprint"] = pin.replace(":", "").lower()
        mport = _q(params, "mport", "")
        if mport:
            proxy["ports"] = mport
        return proxy
    if scheme == "tuic":
        proxy = {**base, "type": "tuic", "uuid": unquote(u.username or ""), "password": unquote(u.password or "")}
        if _q(params, "sni", ""):
            proxy["sni"] = _q(params, "sni")
        if _q(params, "congestion_control", ""):
            proxy["congestion-controller"] = _q(params, "congestion_control")
        if _q(params, "alpn", ""):
            proxy["alpn"] = unquote(_q(params, "alpn")).split(",")
        if _truthy(_q(params, "allow_insecure", "0")) or _truthy(_q(params, "insecure", "0")):
            proxy["skip-cert-verify"] = True
        return proxy
    if scheme in ("socks5", "socks"):
        proxy = {**base, "type": "socks5", "udp": True}
        if u.username:
            proxy["username"] = unquote(u.username)
            proxy["password"] = unquote(u.password or "")
        return proxy
    raise ValueError(f"scheme {scheme} not supported")


def _vmess(line: str) -> dict:
    data = json.loads(_b64decode(line[len("vmess://"):]))
    proxy = {
        "name": data.get("ps") or f"vmess-{data.get('add')}",
        "type": "vmess",
        "server": data["add"],
        "port": int(data["port"]),
        "uuid": data["id"],
        "alterId": int(data.get("aid", 0) or 0),
        "cipher": data.get("scy") or "auto",
        "udp": True,
    }
    params = {"type": [data.get("net", "tcp")], "path": [data.get("path", "/")], "host": [data.get("host", "")]}
    if data.get("tls") == "tls":
        proxy["tls"] = True
        if data.get("sni"):
            proxy["servername"] = data["sni"]
    _transport(proxy, params)
    return proxy


def _ss(line: str) -> dict:
    body = line[len("ss://"):]
    body, _, frag = body.partition("#")
    body = body.split("?", 1)[0]
    if "@" in body:
        userinfo, _, hostport = body.rpartition("@")
        try:
            method_pass = _b64decode(userinfo) if ":" not in unquote(userinfo) else unquote(userinfo)
        except ValueError:
            method_pass = unquote(userinfo)
    else:
        decoded = _b64decode(body)
        method_pass, _, hostport = decoded.rpartition("@")
    method, _, password = method_pass.partition(":")
    host, _, port = hostport.rpartition(":")
    return {"name": unquote(frag) or f"ss-{host}", "type": "ss", "server": host.strip("[]"), "port": int(port),
            "cipher": method, "password": password, "udp": True}


def parse_text(text: str, mlkem: bool = True) -> tuple[list[dict], list[str]]:
    """Parse pasted content: links (plain or base64 block) or a Clash YAML."""
    text = text.strip()
    errors: list[str] = []
    if not text:
        return [], errors
    if "proxies:" in text:
        try:
            doc = yaml.safe_load(text)
            if isinstance(doc, dict) and isinstance(doc.get("proxies"), list):
                return [p for p in doc["proxies"] if isinstance(p, dict) and "name" in p], errors
        except yaml.YAMLError:
            errors.append("yaml: could not parse")
    if "://" not in text:
        try:
            text = _b64decode(text.replace("\n", ""))
        except ValueError:
            errors.append("content is neither links, base64 nor YAML")
            return [], errors
    proxies = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            proxies.append(parse_link(line, mlkem))
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            errors.append(f"{line[:40]}…: {exc}")
    return proxies, errors


# Export -----------------------------------------------------------------

def _transport_params(p: dict) -> dict:
    net = p.get("network", "tcp")
    out = {"type": net if net != "h2" else "http"}
    if net == "ws":
        ws = p.get("ws-opts", {})
        out["path"] = ws.get("path", "/")
        host = ws.get("headers", {}).get("Host")
        if host:
            out["host"] = host
    elif net == "grpc":
        out["serviceName"] = p.get("grpc-opts", {}).get("grpc-service-name", "")
    elif net == "xhttp":
        x = p.get("xhttp-opts", {})
        out["path"] = x.get("path", "/")
        if x.get("host"):
            out["host"] = x["host"]
        if x.get("mode"):
            out["mode"] = x["mode"]
    return out


def to_link(p: dict) -> str:
    name = quote(p["name"])
    server = p["server"]
    host = f"[{server}]" if ":" in server else server
    t = p.get("type")
    if t == "vless":
        params = {"encryption": p.get("encryption", "none"), **_transport_params(p)}
        if p.get("flow"):
            params["flow"] = p["flow"]
        if "reality-opts" in p:
            params.update({"security": "reality", "pbk": p["reality-opts"].get("public-key", ""),
                           "sid": p["reality-opts"].get("short-id", "")})
        elif p.get("tls"):
            params["security"] = "tls"
        if p.get("servername"):
            params["sni"] = p["servername"]
        if p.get("client-fingerprint"):
            params["fp"] = p["client-fingerprint"]
        if p.get("alpn"):
            params["alpn"] = ",".join(p["alpn"])
        return f"vless://{p['uuid']}@{host}:{p['port']}?{urlencode(params)}#{name}"
    if t == "trojan":
        params = {"security": "tls", **_transport_params(p)}
        if p.get("sni"):
            params["sni"] = p["sni"]
        return f"trojan://{quote(p['password'], safe='')}@{host}:{p['port']}?{urlencode(params)}#{name}"
    if t == "hysteria2":
        params = {}
        if p.get("sni"):
            params["sni"] = p["sni"]
        if p.get("obfs"):
            params.update({"obfs": p["obfs"], "obfs-password": p.get("obfs-password", "")})
        if p.get("skip-cert-verify"):
            params["insecure"] = "1"
        if p.get("fingerprint"):
            params["pinSHA256"] = p["fingerprint"]
        if p.get("ports"):
            params["mport"] = p["ports"]
        return f"hysteria2://{quote(p['password'], safe='')}@{host}:{p['port']}?{urlencode(params)}#{name}"
    if t == "vmess":
        data = {"v": "2", "ps": p["name"], "add": server, "port": str(p["port"]), "id": p["uuid"],
                "aid": str(p.get("alterId", 0)), "scy": p.get("cipher", "auto"), "net": p.get("network", "tcp"),
                "type": "none", "host": p.get("ws-opts", {}).get("headers", {}).get("Host", ""),
                "path": p.get("ws-opts", {}).get("path", ""), "tls": "tls" if p.get("tls") else "",
                "sni": p.get("servername", "")}
        return "vmess://" + base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode()
    if t == "ss":
        userinfo = base64.urlsafe_b64encode(f"{p['cipher']}:{p['password']}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{host}:{p['port']}#{name}"
    if t == "tuic":
        params = {k: v for k, v in (("sni", p.get("sni")), ("congestion_control", p.get("congestion-controller")),
                                    ("alpn", ",".join(p.get("alpn", [])) or None)) if v}
        return (f"tuic://{p['uuid']}:{quote(p.get('password', ''), safe='')}@{host}:{p['port']}"
                f"?{urlencode(params)}#{name}")
    if t == "socks5":
        auth = ""
        if p.get("username"):
            auth = f"{quote(p['username'], safe='')}:{quote(p.get('password', ''), safe='')}@"
        return f"socks5://{auth}{host}:{p['port']}#{name}"
    raise ValueError(f"cannot export type {t}")
