import base64
import json

import pytest
import yaml

from app.checks.proxy import parse_proxy
from app.generators import links, mihomo
from app.generators.qr import svg_data_uri
from app.generators.skill_prompt import PlanInput, build_prompt, deploy_config, lxc_config

VLESS = ("vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?encryption=none&flow=xtls-rprx-vision"
         "&security=reality&sni=addons.mozilla.org&fp=chrome&pbk=PUBKEY&sid=ab12&type=tcp#JP%20Reality")
HY2 = "hysteria2://pass%40word@203.0.113.10:8443?sni=example.com&obfs=salamander&obfs-password=ob&pinSHA256=AB:CD#JP%20Hy2"
WS = ("vless://11111111-2222-3333-4444-555555555555@104.16.160.1:443?encryption=none&security=tls&sni=cdn.example.com"
      "&type=ws&host=cdn.example.com&path=%2Fws#CDN%20WS")
TROJAN = "trojan://secret@203.0.113.11:443?sni=t.example.com&type=tcp#Trojan"


def test_vless_reality():
    p = links.parse_link(VLESS)
    assert p["type"] == "vless" and p["flow"] == "xtls-rprx-vision"
    assert p["reality-opts"] == {"public-key": "PUBKEY", "short-id": "ab12", "support-x25519mlkem768": True}
    assert p["servername"] == "addons.mozilla.org"
    assert "support-x25519mlkem768" not in links.parse_link(VLESS, mlkem=False)["reality-opts"]


def test_hy2_and_ws():
    h = links.parse_link(HY2)
    assert h["password"] == "pass@word" and h["obfs"] == "salamander" and h["fingerprint"] == "abcd"
    w = links.parse_link(WS)
    assert w["network"] == "ws" and w["ws-opts"] == {"path": "/ws", "headers": {"Host": "cdn.example.com"}}


@pytest.mark.parametrize("link", [VLESS, HY2, WS, TROJAN])
def test_roundtrip(link):
    p = links.parse_link(link)
    again = links.parse_link(links.to_link(p))
    assert again == p


def test_vmess_and_ss():
    vm = {"v": "2", "ps": "VM", "add": "203.0.113.12", "port": "8080", "id": "uuid-1", "aid": "0",
          "net": "ws", "path": "/v", "host": "h.example.com", "tls": ""}
    p = links.parse_link("vmess://" + base64.b64encode(json.dumps(vm).encode()).decode())
    assert p["type"] == "vmess" and p["ws-opts"]["path"] == "/v"
    ss = "ss://" + base64.urlsafe_b64encode(b"aes-128-gcm:pw").decode().rstrip("=") + "@203.0.113.13:8388#SS"
    s = links.parse_link(ss)
    assert (s["cipher"], s["password"], s["port"]) == ("aes-128-gcm", "pw", 8388)
    assert links.parse_link(links.to_link(s)) == s


def test_parse_text_base64_and_yaml():
    blob = base64.b64encode(f"{VLESS}\n{HY2}\nbogus://x\n".encode()).decode()
    proxies, errors = links.parse_text(blob)
    assert len(proxies) == 2 and len(errors) == 1
    doc = yaml.safe_dump({"proxies": [links.parse_link(TROJAN)]})
    proxies, errors = links.parse_text(doc)
    assert proxies[0]["type"] == "trojan" and not errors


def test_mihomo_build_isolates_metered():
    proxies = [links.parse_link(VLESS), links.parse_link(HY2),
               {**links.parse_link(TROJAN), "name": "US Residential"}]
    opts = mihomo.ConvertOptions(add_flags=True, groups="region", block_ads=True, streaming_group=True)
    proxies = mihomo.transform(proxies, opts)
    assert proxies[0]["name"].startswith("🇯🇵")
    cfg = mihomo.build_config(proxies, opts)
    assert mihomo.check_config(cfg) == []
    groups = {g["name"]: g for g in cfg["proxy-groups"]}
    auto = groups["⚡ Auto (latency)"]["proxies"]
    resi = groups["🏠 Residential & Relay"]["proxies"]
    assert resi[0].endswith("US Residential") and resi[1] == "DIRECT"
    assert resi[0] not in auto
    assert any(name.endswith("JP") for name in groups)
    assert cfg["rules"][-1] == "MATCH,🚀 Proxy"
    yaml.safe_load(mihomo.dump(cfg))


def test_transform_filters_and_unique_names():
    a = links.parse_link(VLESS)
    b = {**links.parse_link(TROJAN), "name": a["name"]}
    opts = mihomo.ConvertOptions(exclude="nothing", renames=[("Reality", "R")], prefix="X-")
    out = mihomo.transform([a, b], opts)
    assert [p["name"] for p in out] == ["X-JP R", "X-JP R 2"]
    assert mihomo.transform([a], mihomo.ConvertOptions(include="^US")) == []
    with pytest.raises(ValueError):
        mihomo.transform([a], mihomo.ConvertOptions(include="("))


def test_simple_groups_valid():
    cfg = mihomo.build_config([links.parse_link(VLESS)], mihomo.ConvertOptions(groups="simple", lang="zh"))
    assert mihomo.check_config(cfg) == []
    assert cfg["proxy-groups"][0]["name"] == "🚀 节点选择"


def test_prompt_has_no_secrets_by_default():
    plan = PlanInput(ip="203.0.113.10", preset="complete", domain="n.example.com", manage_dns=True,
                     exit_proxy="gw.example.com:824", secrets={"ssh_pass": "hunter2", "cf_token": "tok123"})
    cfg = deploy_config(plan)
    assert "ssh_pass" not in cfg and "cf_token" not in cfg
    assert cfg["manage_dns"] is True and cfg["cdn_transport"] == "ws"
    assert cfg["exit_proxy"]["password"] == "<EXIT_PROXY_PASS>"
    text = build_prompt(plan)
    assert "hunter2" not in text and "tok123" not in text
    assert "export VPS_SSH_PASS" in text and "export CF_TOKEN" in text
    assert "./output/203.0.113.10/" in text


def test_prompt_with_secrets_and_lxc():
    plan = PlanInput(ip="203.0.113.10", include_secrets=True, use_lxc=True, traffic_limit_gb=1500,
                     save_location="custom", custom_path="/root/vps/{ip}/", secrets={"ssh_pass": "hunter2"})
    assert deploy_config(plan)["ssh_pass"] == "hunter2"
    assert deploy_config(plan)["output_dir"] == "/root/vps/{ip}/".format(ip="203.0.113.10")
    lxc = lxc_config(plan)
    assert lxc["traffic_limit_gb"] == 1500 and lxc["count"] == 2
    text = build_prompt(plan, {"facts": {}, "findings": [{"level": "warn", "code": "swap_none", "params": {}}]})
    assert "vps-lxc-skill" in text and "WARN swap_none" in text


def test_key_auth_prompt():
    cfg = deploy_config(PlanInput(ip="203.0.113.10", ssh_auth="key", ssh_key_path="~/.ssh/k"))
    assert cfg["ssh_key"] == "~/.ssh/k" and "ssh_pass" not in cfg


def test_parse_proxy_formats():
    a = parse_proxy("socks5://us%40er:p%3Ass@gw.example.com:824")
    assert (a.username, a.password, a.port) == ("us@er", "p:ss", 824)
    assert "p:ss" not in a.display() and "p%3Ass" in a.url()
    b = parse_proxy("gw.example.com:824:user:pa:ss", "http")
    assert (b.scheme, b.password) == ("http", "pa:ss")
    c = parse_proxy("user:pw@1.2.3.4:1080")
    assert (c.host, c.username) == ("1.2.3.4", "user")
    with pytest.raises(ValueError):
        parse_proxy("ftp://x:1")


def test_qr():
    assert svg_data_uri("hello").startswith("data:image/svg+xml;base64,")
    assert svg_data_uri("x" * 5000) is None
